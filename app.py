
import os
import time
import uuid
import json
import math
import hmac
import hashlib
import threading

import oqs

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 65536

# Cryptographic configuration
KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-65"

AES_KEY_LENGTH = 32
AES_NONCE_LENGTH = 12

KEM_PUBLIC_KEY_SIZE = 1184
KEM_CIPHERTEXT_SIZE = 1088

ML_DSA_PUBLIC_KEY_SIZE = 1952
ML_DSA_SIGNATURE_SIZE = 3309

DEVICE_ID = "esp32-energy-01"

# Sessions are held in memory for this demonstration.
sessions = {}
sessions_lock = threading.RLock()

# Authentication token configured in Render environment variables.
API_TOKEN = os.getenv("PQC_API_TOKEN")


def authenticate_request():
    """Authenticate requests using a bearer token."""

    if not API_TOKEN:
        return False

    supplied_token = request.headers.get(
        "Authorization", ""
    )

    expected_token = "Bearer " + API_TOKEN

    return hmac.compare_digest(
        supplied_token,
        expected_token
    )


def require_authentication():
    if not authenticate_request():
        return jsonify({
            "error": "Unauthorized"
        }), 401

    return None


def derive_session_key(shared_secret):
    """Match the ESP32 HKDF-SHA256 configuration."""

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=None,
        info=b"PQC-IoT-Energy:esp32-energy-01"
    )

    return hkdf.derive(shared_secret)


def validate_energy_data(data):
    """Validate all six readings and the message counter."""

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


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "PQC IoT Energy Monitoring Backend",
        "mode": "End-to-End PQC"
    }), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy"
    }), 200


@app.route("/pqc-test", methods=["GET"])
def pqc_test():
    try:
        kem_algorithms = oqs.get_enabled_kem_mechanisms()
        signature_algorithms = oqs.get_enabled_sig_mechanisms()

        return jsonify({
            "pqc_library": "available",
            "ml_kem_768": KEM_ALGORITHM in kem_algorithms,
            "ml_dsa_65": SIGNATURE_ALGORITHM in signature_algorithms
        }), 200

    except Exception:
        app.logger.exception("PQC capability test failed")

        return jsonify({
            "pqc_library": "unavailable"
        }), 500


# --------------------------------------------------
# CREATE AN END-TO-END KEM SESSION
# --------------------------------------------------

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

        return jsonify({
            "error": "Session creation failed"
        }), 500


# --------------------------------------------------
# RECEIVE ESP32 ML-KEM CIPHERTEXT
# --------------------------------------------------

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

        ciphertext_hex = body.get("ciphertext")

        if not isinstance(ciphertext_hex, str):
            return jsonify({"error": "Missing ciphertext"}), 400

        if len(ciphertext_hex) != KEM_CIPHERTEXT_SIZE * 2:
            return jsonify({"error": "Invalid KEM ciphertext length"}), 400

        ciphertext = bytes.fromhex(ciphertext_hex)

        with sessions_lock:
            session = sessions.get(session_id)

            if session is None:
                return jsonify({"error": "Unknown session"}), 404

            shared_secret = session["kem"].decap_secret(ciphertext)

            aes_key = derive_session_key(shared_secret)

            session["aes_key"] = aes_key

        fingerprint = hashlib.sha256(aes_key).hexdigest()

        app.logger.info(
            "ML-KEM decapsulation and HKDF successful"
        )

        return jsonify({
            "status": "decapsulation_successful",
            "key_fingerprint": fingerprint
        }), 200

    except ValueError:
        return jsonify({"error": "Invalid ciphertext encoding"}), 400

    except Exception:
        app.logger.exception("KEM decapsulation failed")

        return jsonify({
            "error": "KEM decapsulation failed"
        }), 500


# --------------------------------------------------
# REGISTER ESP32 ML-DSA PUBLIC KEY
# --------------------------------------------------

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

        public_key_hex = body.get("public_key")

        if not isinstance(public_key_hex, str):
            return jsonify({"error": "Missing public key"}), 400

        if len(public_key_hex) != ML_DSA_PUBLIC_KEY_SIZE * 2:
            return jsonify({"error": "Invalid ML-DSA public key length"}), 400

        public_key = bytes.fromhex(public_key_hex)

        with sessions_lock:
            session = sessions.get(session_id)

            if session is None:
                return jsonify({"error": "Unknown session"}), 404

            session["signature_public_key"] = public_key

        app.logger.info("ESP32 ML-DSA public key registered")

        return jsonify({
            "status": "signature_public_key_registered"
        }), 200

    except ValueError:
        return jsonify({"error": "Invalid public key encoding"}), 400

    except Exception:
        app.logger.exception("Public key registration failed")

        return jsonify({
            "error": "Public key registration failed"
        }), 500


# --------------------------------------------------
# RECEIVE, DECRYPT AND VERIFY ENERGY DATA
# --------------------------------------------------

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

        if not isinstance(body, dict):
            return jsonify({"error": "Invalid JSON"}), 400

        nonce_hex = body.get("nonce")
        ciphertext_hex = body.get("ciphertext")
        signature_hex = body.get("signature")

        if not all(
            isinstance(value, str)
            for value in (
                nonce_hex,
                ciphertext_hex,
                signature_hex
            )
        ):
            return jsonify({
                "error": "Incomplete encrypted envelope"
            }), 400

        if len(nonce_hex) != AES_NONCE_LENGTH * 2:
            return jsonify({"error": "Invalid nonce length"}), 400

        if len(signature_hex) != ML_DSA_SIGNATURE_SIZE * 2:
            return jsonify({"error": "Invalid signature length"}), 400

        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        signature = bytes.fromhex(signature_hex)

        with sessions_lock:
            session = sessions.get(session_id)

            if session is None:
                return jsonify({"error": "Unknown session"}), 404

            if session["aes_key"] is None:
                return jsonify({
                    "error": "KEM session not established"
                }), 400

            if session["signature_public_key"] is None:
                return jsonify({
                    "error": "Signature public key not registered"
                }), 400

            aes_key = session["aes_key"]
            public_key = session["signature_public_key"]

            # AES-GCM authentication and decryption.
            plaintext = AESGCM(aes_key).decrypt(
                nonce,
                ciphertext,
                None
            )

            # Verify the signature over the exact original plaintext.
            with oqs.Signature(SIGNATURE_ALGORITHM) as verifier:
                signature_valid = verifier.verify(
                    plaintext,
                    signature,
                    public_key
                )

            if not signature_valid:
                return jsonify({
                    "error": "ML-DSA signature verification failed"
                }), 401

            energy_data = json.loads(
                plaintext.decode("utf-8")
            )

            counter = validate_energy_data(energy_data)

            if counter <= session["last_counter"]:
                return jsonify({
                    "error": "Replay detected or invalid counter"
                }), 409

            # Update only after successful decryption,
            # signature verification and data validation.
            session["last_counter"] = counter

        app.logger.info(
            "End-to-end energy message accepted: counter=%d",
            counter
        )

        return jsonify({
            "status": "success",
            "device_id": DEVICE_ID,
            "counter": counter,
            "signature": "verified",
            "encryption": "AES-256-GCM verified",
            "replay_protection": "passed",
            "energy_data": energy_data
        }), 200

    except json.JSONDecodeError:
        return jsonify({"error": "Invalid energy JSON"}), 400

    except UnicodeDecodeError:
        return jsonify({"error": "Invalid plaintext encoding"}), 400

    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    except Exception:
        app.logger.exception("Energy message processing failed")

        return jsonify({
            "error": "Energy message authentication or processing failed"
        }), 400


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "10000"))
    )
