
import os
import time
import uuid
import json
import math
import hmac
import hashlib
import threading
import ssl

import oqs
import paho.mqtt.client as mqtt

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 65536

KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-65"

AES_KEY_LENGTH = 32
AES_NONCE_LENGTH = 12

KEM_PUBLIC_KEY_SIZE = 1184
KEM_CIPHERTEXT_SIZE = 1088

ML_DSA_PUBLIC_KEY_SIZE = 1952
ML_DSA_SIGNATURE_SIZE = 3309

DEVICE_ID = "esp32-energy-01"

EMQX_HOST = os.getenv("EMQX_HOST")
EMQX_PORT = int(os.getenv("EMQX_PORT", "8883"))
EMQX_USERNAME = os.getenv("EMQX_USERNAME")
EMQX_PASSWORD = os.getenv("EMQX_PASSWORD")

TOPIC_SESSION = "pqc_energy/e2e/session"
TOPIC_KEM = "pqc_energy/e2e/kem"
TOPIC_SIGNATURE = "pqc_energy/e2e/signature"
TOPIC_ENERGY = "pqc_energy/e2e/energy"

API_TOKEN = os.getenv("PQC_API_TOKEN")

sessions = {}
sessions_lock = threading.RLock()

energy_history = []
history_lock = threading.RLock()

mqtt_client = None
mqtt_started = False
mqtt_start_lock = threading.Lock()


def authenticate_request():
    if not API_TOKEN:
        return False

    supplied_token = request.headers.get("Authorization", "")
    expected_token = "Bearer " + API_TOKEN

    return hmac.compare_digest(supplied_token, expected_token)


def require_authentication():
    if not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401

    return None


def derive_session_key(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=None,
        info=b"PQC-IoT-Energy:esp32-energy-01"
    )

    return hkdf.derive(shared_secret)


def validate_energy_data(data):
    required_fields = [
        "voltage",
        "current",
        "power",
        "energy",
        "frequency",
        "pf",
        "counter"
    ]

    if not isinstance(data, dict):
        raise ValueError("Energy data must be a JSON object")

    for field in required_fields:
        if field not in data:
            raise ValueError("Missing field: " + field)

    counter = data["counter"]

    if (
        not isinstance(counter, int)
        or isinstance(counter, bool)
        or counter < 1
    ):
        raise ValueError("Invalid message counter")

    for field in required_fields[:-1]:
        value = data[field]

        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
        ):
            raise ValueError("Invalid reading: " + field)

    if data["voltage"] <= 0:
        raise ValueError("Invalid voltage")

    if data["current"] < 0 or data["power"] < 0:
        raise ValueError("Invalid current or power")

    if data["energy"] < 0:
        raise ValueError("Invalid energy")

    if data["frequency"] <= 0:
        raise ValueError("Invalid frequency")

    if not 0 <= data["pf"] <= 1:
        raise ValueError("Invalid power factor")

    return counter


def get_session(session_id):
    with sessions_lock:
        return sessions.get(session_id)


def process_kem_ciphertext(session_id, ciphertext_hex):
    if not isinstance(ciphertext_hex, str):
        raise ValueError("Missing KEM ciphertext")

    if len(ciphertext_hex) != KEM_CIPHERTEXT_SIZE * 2:
        raise ValueError("Invalid KEM ciphertext length")

    ciphertext = bytes.fromhex(ciphertext_hex)

    with sessions_lock:
        session = sessions.get(session_id)

        if session is None:
            raise LookupError("Unknown session")

        shared_secret = session["kem"].decap_secret(ciphertext)
        aes_key = derive_session_key(shared_secret)
        session["aes_key"] = aes_key

    fingerprint = hashlib.sha256(aes_key).hexdigest()

    app.logger.info("ML-KEM decapsulation and HKDF successful")
    app.logger.info("AES key fingerprint: %s", fingerprint)

    return {
        "status": "decapsulation_successful",
        "key_fingerprint": fingerprint
    }


def process_signature_public_key(session_id, public_key_hex):
    if not isinstance(public_key_hex, str):
        raise ValueError("Missing ML-DSA public key")

    if len(public_key_hex) != ML_DSA_PUBLIC_KEY_SIZE * 2:
        raise ValueError("Invalid ML-DSA public key length")

    public_key = bytes.fromhex(public_key_hex)

    with sessions_lock:
        session = sessions.get(session_id)

        if session is None:
            raise LookupError("Unknown session")

        session["signature_public_key"] = public_key

    app.logger.info("ESP32 ML-DSA public key registered")

    return {
        "status": "signature_public_key_registered"
    }


def process_energy_envelope(session_id, body):
    if not isinstance(body, dict):
        raise ValueError("Invalid encrypted envelope")

    nonce_hex = body.get("nonce")
    ciphertext_hex = body.get("ciphertext")
    signature_hex = body.get("signature")

    if not all(
        isinstance(value, str)
        for value in (nonce_hex, ciphertext_hex, signature_hex)
    ):
        raise ValueError("Incomplete encrypted envelope")

    if len(nonce_hex) != AES_NONCE_LENGTH * 2:
        raise ValueError("Invalid nonce length")

    if len(signature_hex) != ML_DSA_SIGNATURE_SIZE * 2:
        raise ValueError("Invalid signature length")

    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    signature = bytes.fromhex(signature_hex)

    with sessions_lock:
        session = sessions.get(session_id)

        if session is None:
            raise LookupError("Unknown session")

        if session["aes_key"] is None:
            raise ValueError("KEM session not established")

        if session["signature_public_key"] is None:
            raise ValueError("Signature public key not registered")

        plaintext = AESGCM(session["aes_key"]).decrypt(
            nonce,
            ciphertext,
            None
        )

        with oqs.Signature(SIGNATURE_ALGORITHM) as verifier:
            signature_valid = verifier.verify(
                plaintext,
                signature,
                session["signature_public_key"]
            )

        if not signature_valid:
            raise PermissionError("ML-DSA signature verification failed")

        energy_data = json.loads(plaintext.decode("utf-8"))
        counter = validate_energy_data(energy_data)

        if counter <= session["last_counter"]:
            raise ValueError("Replay detected or invalid counter")

        session["last_counter"] = counter

    reading = {
        "device_id": DEVICE_ID,
        "counter": counter,
        "timestamp": time.time(),
        "signature": "verified",
        "encryption": "AES-256-GCM verified",
        "replay_protection": "passed",
        "energy_data": energy_data
    }

    with history_lock:
        energy_history.append(reading)

        if len(energy_history) > 500:
            del energy_history[:-500]

    app.logger.info(
        "Energy message verified successfully: counter=%d",
        counter
    )

    return {
        "status": "success",
        **reading
    }


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "PQC IoT Energy Monitoring Backend",
        "mode": "End-to-End PQC with EMQX"
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "mqtt_connected": (
            mqtt_client.is_connected()
            if mqtt_client else False
        )
    }), 200


@app.route("/pqc-test", methods=["GET"])
def pqc_test():
    try:
        return jsonify({
            "pqc_library": "available",
            "ml_kem_768": (
                KEM_ALGORITHM in oqs.get_enabled_kem_mechanisms()
            ),
            "ml_dsa_65": (
                SIGNATURE_ALGORITHM in oqs.get_enabled_sig_mechanisms()
            )
        }), 200

    except Exception:
        app.logger.exception("PQC capability test failed")
        return jsonify({"pqc_library": "unavailable"}), 500


@app.route("/api/sessions", methods=["POST"])
def create_session():
    auth_error = require_authentication()

    if auth_error:
        return auth_error

    try:
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
        public_key = kem.generate_keypair()

        if len(public_key) != KEM_PUBLIC_KEY_SIZE:
            kem.free()
            raise ValueError("Unexpected ML-KEM public key size")

        session_id = str(uuid.uuid4())

        session_data = {
            "kem": kem,
            "aes_key": None,
            "signature_public_key": None,
            "last_counter": 0,
            "created_at": time.time()
        }

        with sessions_lock:
            sessions[session_id] = session_data

        app.logger.info("New end-to-end PQC session created")

        return jsonify({
            "session_id": session_id,
            "algorithm": KEM_ALGORITHM,
            "public_key": public_key.hex()
        }), 201

    except Exception:
        app.logger.exception("Session creation failed")
        return jsonify({"error": "Session creation failed"}), 500


@app.route(
    "/api/sessions/<session_id>/kem-ciphertext",
    methods=["POST"]
)
def receive_kem_ciphertext(session_id):
    auth_error = require_authentication()

    if auth_error:
        return auth_error

    try:
        body = request.get_json(silent=True)

        if not isinstance(body, dict):
            return jsonify({"error": "Invalid JSON"}), 400

        result = process_kem_ciphertext(
            session_id,
            body.get("ciphertext")
        )

        return jsonify(result), 200

    except LookupError as error:
        return jsonify({"error": str(error)}), 404

    except Exception as error:
        app.logger.exception("KEM processing failed")
        return jsonify({"error": str(error)}), 400


@app.route(
    "/api/sessions/<session_id>/signature-public-key",
    methods=["POST"]
)
def register_signature_public_key(session_id):
    auth_error = require_authentication()

    if auth_error:
        return auth_error

    try:
        body = request.get_json(silent=True)

        if not isinstance(body, dict):
            return jsonify({"error": "Invalid JSON"}), 400

        result = process_signature_public_key(
            session_id,
            body.get("public_key")
        )

        return jsonify(result), 200

    except LookupError as error:
        return jsonify({"error": str(error)}), 404

    except Exception as error:
        app.logger.exception("Signature key registration failed")
        return jsonify({"error": str(error)}), 400


@app.route(
    "/api/sessions/<session_id>/energy",
    methods=["POST"]
)
def receive_energy(session_id):
    auth_error = require_authentication()

    if auth_error:
        return auth_error

    try:
        body = request.get_json(silent=True)

        result = process_energy_envelope(session_id, body)

        return jsonify(result), 200

    except LookupError as error:
        return jsonify({"error": str(error)}), 404

    except PermissionError as error:
        return jsonify({"error": str(error)}), 401

    except Exception as error:
        app.logger.exception("Energy processing failed")
        return jsonify({"error": str(error)}), 400


@app.route("/api/readings", methods=["GET"])
def get_readings():
    auth_error = require_authentication()

    if auth_error:
        return auth_error

    try:
        limit = int(request.args.get("limit", "100"))
        limit = max(1, min(limit, 500))

        with history_lock:
            readings = list(energy_history[-limit:])

        return jsonify({
            "status": "success",
            "count": len(readings),
            "readings": readings
        }), 200

    except ValueError:
        return jsonify({"error": "Invalid limit"}), 400


def on_mqtt_connect(client, userdata, flags, reason_code, properties):
    if reason_code.is_failure:
        app.logger.error("EMQX connection failed: %s", reason_code)
        return

    app.logger.info("Connected to EMQX Cloud")

    topics = [
        (TOPIC_SESSION, 1),
        (TOPIC_KEM, 1),
        (TOPIC_SIGNATURE, 1),
        (TOPIC_ENERGY, 1)
    ]

    client.subscribe(topics)

    app.logger.info("Subscribed to E2E MQTT topics")


def on_mqtt_message(client, userdata, message):
    try:
        payload = json.loads(message.payload.decode("utf-8"))

        if not isinstance(payload, dict):
            raise ValueError("MQTT payload must be a JSON object")

        session_id = payload.get("session_id")

        if message.topic == TOPIC_SESSION:
            if not session_id or get_session(session_id) is None:
                raise LookupError("Unknown MQTT session notification")

            app.logger.info("EMQX session notification received")
            return

        if not isinstance(session_id, str):
            raise ValueError("Missing session_id in MQTT message")

        if message.topic == TOPIC_KEM:
            result = process_kem_ciphertext(
                session_id,
                payload.get("ciphertext")
            )

            app.logger.info(
                "EMQX KEM message processed: %s",
                result["status"]
            )

        elif message.topic == TOPIC_SIGNATURE:
            result = process_signature_public_key(
                session_id,
                payload.get("public_key")
            )

            app.logger.info(
                "EMQX signature key processed: %s",
                result["status"]
            )

        elif message.topic == TOPIC_ENERGY:
            result = process_energy_envelope(
                session_id,
                payload
            )

            app.logger.info(
                "EMQX energy message verified: counter=%s",
                result["counter"]
            )

    except Exception:
        app.logger.exception(
            "EMQX message processing failed on topic %s",
            message.topic
        )


def start_mqtt_subscriber():
    global mqtt_client, mqtt_started

    with mqtt_start_lock:
        if mqtt_started:
            return

        if not all([
            EMQX_HOST,
            EMQX_USERNAME,
            EMQX_PASSWORD
        ]):
            app.logger.error("EMQX environment variables are missing")
            return

        try:
            client = mqtt.Client(
                mqtt.CallbackAPIVersion.VERSION2,
                client_id="pqc_energy_render",
                protocol=mqtt.MQTTv311
            )

            client.username_pw_set(
                EMQX_USERNAME,
                EMQX_PASSWORD
            )

            client.tls_set_context(ssl.create_default_context())

            client.on_connect = on_mqtt_connect
            client.on_message = on_mqtt_message

            client.reconnect_delay_set(
                min_delay=1,
                max_delay=30
            )

            client.connect_async(
                EMQX_HOST,
                EMQX_PORT,
                keepalive=60
            )

            client.loop_start()

            mqtt_client = client
            mqtt_started = True

            app.logger.info("EMQX MQTT subscriber started")

        except Exception:
            app.logger.exception("Could not start EMQX subscriber")


start_mqtt_subscriber()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "10000"))
    )
