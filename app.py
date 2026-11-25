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

from flask import Flask, jsonify, request, render_template_string
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


@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template_string(DASHBOARD_HTML)


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


DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#080d18">
<title>PQ Energy Monitor</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
    color-scheme: dark;
    --bg: #080d18;
    --panel: #111a2b;
    --panel2: #0d1524;
    --line: #24334b;
    --muted: #91a2ba;
    --text: #edf5ff;
    --cyan: #35d8f2;
    --green: #35df9a;
    --amber: #ffc66b;
    --red: #ff6b78;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    background: radial-gradient(circle at 50% -20%, #1b3150 0, var(--bg) 48%);
    color: var(--text);
    font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
    min-height: 100vh;
}
.wrap { width: min(1240px, 94%); margin: 0 auto; padding: 28px 0 42px; }
header {
    display: flex; justify-content: space-between; align-items: center;
    gap: 16px; flex-wrap: wrap; margin-bottom: 24px;
}
.brand { display: flex; align-items: center; gap: 13px; }
.logo {
    width: 46px; height: 46px; border-radius: 14px;
    display: grid; place-items: center; font-size: 23px;
    color: var(--cyan); background: #123044; border: 1px solid #28627b;
    box-shadow: 0 0 28px #20c8ee20;
}
h1 { margin: 0; font-size: clamp(21px, 3vw, 29px); letter-spacing: .3px; }
.subtitle { color: var(--muted); font-size: 13px; margin-top: 5px; }
.status {
    display: flex; align-items: center; gap: 9px; border: 1px solid var(--line);
    background: #101a2b; border-radius: 30px; padding: 10px 14px;
    color: var(--muted); font-size: 12px;
}
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--amber); }
.dot.live { background: var(--green); box-shadow: 0 0 12px var(--green); }
.panel {
    background: linear-gradient(145deg, #131e31, #0e1727);
    border: 1px solid var(--line); border-radius: 18px;
    box-shadow: 0 14px 35px #0003;
}
.login {
    max-width: 460px; margin: 55px auto; padding: 26px;
}
.login h2 { margin: 0 0 8px; font-size: 21px; }
.login p { color: var(--muted); font-size: 14px; line-height: 1.6; }
input {
    width: 100%; padding: 13px 14px; margin: 10px 0;
    border-radius: 10px; border: 1px solid #344760; background: #091321;
    color: var(--text); font-size: 14px; outline: none;
}
input:focus { border-color: var(--cyan); }
button {
    border: 0; background: linear-gradient(90deg, #16a9ce, #2879d7);
    color: white; font-weight: 700; padding: 13px 18px;
    border-radius: 10px; cursor: pointer; width: 100%; font-size: 14px;
}
button:hover { filter: brightness(1.12); }
.error { color: var(--red); min-height: 20px; font-size: 13px; }
.hidden { display: none !important; }
.section-title {
    display: flex; justify-content: space-between; align-items: end;
    gap: 12px; margin: 26px 2px 13px;
}
.section-title h2 { margin: 0; font-size: 17px; }
.section-title span { color: var(--muted); font-size: 12px; }
.gauges {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 15px;
}
.gauge-card { padding: 17px 13px 15px; text-align: center; min-width: 0; }
.gauge-name { color: #b9c8dc; font-size: 13px; font-weight: 650; letter-spacing: .6px; }
.gauge {
    width: 100%; max-width: 245px; display: block; margin: 4px auto -2px;
    overflow: visible;
}
.gauge-track {
    fill: none; stroke: #293b54; stroke-width: 13; stroke-linecap: round;
}
.gauge-progress {
    fill: none; stroke: var(--cyan); stroke-width: 13; stroke-linecap: round;
    stroke-dasharray: 345.6; stroke-dashoffset: 345.6;
    transition: stroke-dashoffset 1s ease, stroke .5s ease;
    filter: drop-shadow(0 0 5px #35d8f277);
}
.needle {
    stroke: #f2f7ff; stroke-width: 3.5; stroke-linecap: round;
    transform-origin: 130px 130px; transform: rotate(-135deg);
    transition: transform 1s cubic-bezier(.2,.8,.2,1);
}
.hub { fill: #eaf7ff; stroke: #17283e; stroke-width: 5; }
.gauge-value { font-size: 27px; font-weight: 750; fill: #f4f8ff; text-anchor: middle; }
.gauge-unit { font-size: 11px; fill: #91a2ba; text-anchor: middle; }
.gauge-range { display: flex; justify-content: space-between; color: #71839c; font-size: 10px; padding: 0 12px; margin-top: -7px; }
.metric-grid {
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 15px; margin-top: 15px;
}
.metric { padding: 17px 19px; }
.metric-label { color: var(--muted); font-size: 12px; }
.metric-value { font-size: 25px; font-weight: 750; margin-top: 6px; }
.metric-value small { color: var(--muted); font-size: 12px; font-weight: 500; }
.chart-panel { padding: 19px; margin-top: 15px; }
.chart-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 12px; }
.chart-head h2 { font-size: 16px; margin: 0; }
.chart-wrap { height: 260px; position: relative; }
.security {
    display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px; margin-top: 15px;
}
.security-item {
    padding: 16px; display: flex; justify-content: space-between; align-items: center;
    gap: 8px; font-size: 13px;
}
.pill {
    color: var(--green); background: #10372e; border: 1px solid #1d684e;
    padding: 5px 9px; border-radius: 20px; font-size: 10px; font-weight: 750;
    white-space: nowrap;
}
.pill.wait { color: var(--amber); background: #3b2d17; border-color: #735324; }
.footer {
    color: #70819a; text-align: center; font-size: 11px; margin-top: 24px;
}
#lastUpdate { color: var(--muted); font-size: 11px; }
@media (max-width: 850px) {
    .gauges { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 520px) {
    .wrap { width: 93%; padding-top: 18px; }
    .gauges { gap: 9px; }
    .gauge-card { padding: 14px 7px; }
    .gauge-value { font-size: 24px; }
    .security { grid-template-columns: 1fr; gap: 8px; }
    .chart-wrap { height: 220px; }
}
</style>
</head>
<body>
<div class="wrap">
    <header>
        <div class="brand">
            <div class="logo">ϟ</div>
            <div>
                <h1>PQ Energy Monitor</h1>
                <div class="subtitle">Post-quantum secured IoT energy dashboard</div>
            </div>
        </div>
        <div class="status">
            <span class="dot" id="liveDot"></span>
            <span id="connectionText">NOT CONNECTED</span>
        </div>
    </header>

    <section class="panel login" id="loginPanel">
        <h2>Connect to your energy monitor</h2>
        <p>Enter the Render API token configured as <b>PQC_API_TOKEN</b>. It is held only in this browser tab and is not saved.</p>
        <input id="apiToken" type="password" autocomplete="off" placeholder="Enter API token">
        <button id="connectButton" type="button">Connect dashboard</button>
        <div class="error" id="loginError"></div>
    </section>

    <main id="dashboard" class="hidden">
        <div class="section-title">
            <h2>Live electrical measurements</h2>
            <span id="lastUpdate">Waiting for readings...</span>
        </div>

        <section class="gauges">
            <div class="panel gauge-card">
                <div class="gauge-name">VOLTAGE</div>
                <svg class="gauge" viewBox="0 0 260 155" role="img" aria-label="Voltage meter">
                    <path class="gauge-track" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <path class="gauge-progress" id="voltageArc" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <line class="needle" id="voltageNeedle" x1="130" y1="130" x2="130" y2="43"/>
                    <circle class="hub" cx="130" cy="130" r="8"/>
                    <text class="gauge-value" id="voltageValue" x="130" y="112">--</text>
                    <text class="gauge-unit" x="130" y="126">VOLTS</text>
                </svg>
                <div class="gauge-range"><span>0</span><span>150</span><span>300 V</span></div>
            </div>

            <div class="panel gauge-card">
                <div class="gauge-name">CURRENT</div>
                <svg class="gauge" viewBox="0 0 260 155" role="img" aria-label="Current meter">
                    <path class="gauge-track" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <path class="gauge-progress" id="currentArc" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <line class="needle" id="currentNeedle" x1="130" y1="130" x2="130" y2="43"/>
                    <circle class="hub" cx="130" cy="130" r="8"/>
                    <text class="gauge-value" id="currentValue" x="130" y="112">--</text>
                    <text class="gauge-unit" x="130" y="126">AMPERES</text>
                </svg>
                <div class="gauge-range"><span>0</span><span>5</span><span>10 A</span></div>
            </div>

            <div class="panel gauge-card">
                <div class="gauge-name">POWER</div>
                <svg class="gauge" viewBox="0 0 260 155" role="img" aria-label="Power meter">
                    <path class="gauge-track" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <path class="gauge-progress" id="powerArc" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <line class="needle" id="powerNeedle" x1="130" y1="130" x2="130" y2="43"/>
                    <circle class="hub" cx="130" cy="130" r="8"/>
                    <text class="gauge-value" id="powerValue" x="130" y="112">--</text>
                    <text class="gauge-unit" x="130" y="126">WATTS</text>
                </svg>
                <div class="gauge-range"><span>0</span><span>1250</span><span>2500 W</span></div>
            </div>

            <div class="panel gauge-card">
                <div class="gauge-name">ENERGY</div>
                <svg class="gauge" viewBox="0 0 260 155" role="img" aria-label="Energy meter">
                    <path class="gauge-track" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <path class="gauge-progress" id="energyArc" d="M 20 130 A 110 110 0 0 1 240 130"/>
                    <line class="needle" id="energyNeedle" x1="130" y1="130" x2="130" y2="43"/>
                    <circle class="hub" cx="130" cy="130" r="8"/>
                    <text class="gauge-value" id="energyValue" x="130" y="112">--</text>
                    <text class="gauge-unit" x="130" y="126">KWH</text>
                </svg>
                <div class="gauge-range"><span>0</span><span>0.025</span><span>0.05 kWh</span></div>
            </div>
        </section>

        <section class="metric-grid">
            <div class="panel metric">
                <div class="metric-label">FREQUENCY</div>
                <div class="metric-value"><span id="frequencyValue">--</span> <small>Hz</small></div>
            </div>
            <div class="panel metric">
                <div class="metric-label">POWER FACTOR</div>
                <div class="metric-value" id="pfValue">--</div>
            </div>
        </section>

        <section class="panel chart-panel">
            <div class="chart-head">
                <h2>Power consumption history</h2>
                <span class="subtitle">Watts · latest readings</span>
            </div>
            <div class="chart-wrap">
                <canvas id="powerChart"></canvas>
            </div>
        </section>

        <div class="section-title">
            <h2>Post-quantum security</h2>
            <span id="deviceLabel">Device: esp32-energy-01</span>
        </div>
        <section class="security">
            <div class="panel security-item">
                <span>AES-256-GCM encryption</span>
                <span class="pill" id="encryptionStatus">WAITING</span>
            </div>
            <div class="panel security-item">
                <span>ML-DSA-65 signature</span>
                <span class="pill" id="signatureStatus">WAITING</span>
            </div>
            <div class="panel security-item">
                <span>Replay protection</span>
                <span class="pill" id="replayStatus">WAITING</span>
            </div>
        </section>
    </main>

    <div class="footer">PQC IoT Smart Energy Monitoring System · Live data from secured MQTT pipeline</div>
</div>

<script>
let apiToken = "";
let powerChart = null;
let pollHandle = null;

const gaugeSettings = {
    voltage: { max: 300, decimals: 1 },
    current: { max: 10, decimals: 2 },
    power: { max: 2500, decimals: 1 },
    energy: { max: 0.05, decimals: 5 }
};

function setGauge(name, value) {
    const setting = gaugeSettings[name];
    const safeValue = Number.isFinite(Number(value)) ? Number(value) : 0;
    const ratio = Math.max(0, Math.min(1, safeValue / setting.max));
    const arc = document.getElementById(name + "Arc");
    const needle = document.getElementById(name + "Needle");
    const valueText = document.getElementById(name + "Value");

    arc.style.strokeDashoffset = String(345.6 * (1 - ratio));
    needle.style.transform = "rotate(" + (-135 + 270 * ratio) + "deg)";
    valueText.textContent = safeValue.toFixed(setting.decimals);
}

function setSecurityStatus(id, passed) {
    const element = document.getElementById(id);
    element.textContent = passed ? "VERIFIED" : "NOT VERIFIED";
    element.classList.toggle("wait", !passed);
}

function initializeChart() {
    if (typeof Chart === "undefined") {
        document.querySelector(".chart-wrap").innerHTML =
            '<p class="subtitle">Chart library could not load. The live meter readings are still available.</p>';
        return;
    }

    const context = document.getElementById("powerChart").getContext("2d");
    powerChart = new Chart(context, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Power (W)",
                data: [],
                borderColor: "#35d8f2",
                backgroundColor: "rgba(53, 216, 242, 0.12)",
                borderWidth: 2.5,
                fill: true,
                tension: 0.35,
                pointRadius: 2.5,
                pointBackgroundColor: "#35d8f2"
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 450 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#101b2d",
                    titleColor: "#edf5ff",
                    bodyColor: "#35d8f2",
                    borderColor: "#2a405d",
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(145,162,186,.08)" },
                    ticks: { color: "#91a2ba", maxTicksLimit: 8 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(145,162,186,.12)" },
                    ticks: { color: "#91a2ba" },
                    title: { display: true, text: "Watts", color: "#91a2ba" }
                }
            }
        }
    });
}

function showConnection(connected, message) {
    document.getElementById("liveDot").classList.toggle("live", connected);
    document.getElementById("connectionText").textContent =
        message || (connected ? "LIVE DATA" : "CONNECTION LOST");
}

function displayReading(reading) {
    const data = reading.energy_data || {};
    setGauge("voltage", data.voltage);
    setGauge("current", data.current);
    setGauge("power", data.power);
    setGauge("energy", data.energy);

    document.getElementById("frequencyValue").textContent =
        Number(data.frequency).toFixed(1);
    document.getElementById("pfValue").textContent =
        Number(data.pf).toFixed(2);
    document.getElementById("deviceLabel").textContent =
        "Device: " + (reading.device_id || "ESP32");

    setSecurityStatus(
        "encryptionStatus",
        reading.encryption === "AES-256-GCM verified"
    );
    setSecurityStatus("signatureStatus", reading.signature === "verified");
    setSecurityStatus(
        "replayStatus",
        reading.replay_protection === "passed"
    );
}

function updateChart(readings) {
    if (!powerChart) return;

    const points = readings.slice(-40);
    powerChart.data.labels = points.map(item => {
        const date = new Date(item.timestamp * 1000);
        return date.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    });
    powerChart.data.datasets[0].data =
        points.map(item => Number(item.energy_data.power));
    powerChart.update();
}

async function refreshReadings() {
    try {
        const response = await fetch("/api/readings?limit=100", {
            method: "GET",
            headers: { "Authorization": "Bearer " + apiToken },
            cache: "no-store"
        });

        if (response.status === 401) {
            disconnectDashboard("API token was rejected. Enter it again.");
            return;
        }

        if (!response.ok) {
            throw new Error("Server returned HTTP " + response.status);
        }

        const result = await response.json();
        const readings = result.readings || [];

        if (readings.length > 0) {
            const latest = readings[readings.length - 1];
            displayReading(latest);
            updateChart(readings);
            document.getElementById("lastUpdate").textContent =
                "Updated " + new Date().toLocaleTimeString();
            showConnection(true, "LIVE · " + readings.length + " READINGS");
        } else {
            showConnection(false, "WAITING FOR DATA");
            document.getElementById("lastUpdate").textContent =
                "No verified readings received yet";
        }
    } catch (error) {
        showConnection(false, "CONNECTION LOST");
        document.getElementById("lastUpdate").textContent = error.message;
    }
}

function disconnectDashboard(message) {
    apiToken = "";
    if (pollHandle) clearInterval(pollHandle);
    pollHandle = null;
    document.getElementById("dashboard").classList.add("hidden");
    document.getElementById("loginPanel").classList.remove("hidden");
    document.getElementById("loginError").textContent = message || "";
    showConnection(false, "NOT CONNECTED");
}

async function connectDashboard() {
    const input = document.getElementById("apiToken");
    const suppliedToken = input.value.trim();
    const errorElement = document.getElementById("loginError");

    if (!suppliedToken) {
        errorElement.textContent = "Enter your API token to continue.";
        return;
    }

    apiToken = suppliedToken;
    errorElement.textContent = "Checking token...";
    document.getElementById("connectButton").disabled = true;

    try {
        const response = await fetch("/api/readings?limit=1", {
            headers: { "Authorization": "Bearer " + apiToken },
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(
                response.status === 401 ? "Incorrect API token." :
                "Unable to connect. HTTP " + response.status
            );
        }

        input.value = "";
        document.getElementById("loginPanel").classList.add("hidden");
        document.getElementById("dashboard").classList.remove("hidden");
        errorElement.textContent = "";

        initializeChart();
        await refreshReadings();

        if (pollHandle) clearInterval(pollHandle);
        pollHandle = setInterval(refreshReadings, 2000);
    } catch (error) {
        apiToken = "";
        errorElement.textContent = error.message;
    } finally {
        document.getElementById("connectButton").disabled = false;
    }
}

document.getElementById("connectButton").addEventListener("click", connectDashboard);
document.getElementById("apiToken").addEventListener("keydown", event => {
    if (event.key === "Enter") connectDashboard();
});
</script>
</body>
</html>
"""


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
