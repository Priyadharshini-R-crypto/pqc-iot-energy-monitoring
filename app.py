
from flask import Flask, jsonify

app = Flask(__name__)

cloud_kem = None
cloud_public_key = None

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "service": "PQC IoT Energy Monitoring Backend"
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route("/pqc-test", methods=["GET"])
def pqc_test():
    try:
        import oqs
        algorithms = oqs.get_enabled_kem_mechanisms()
        return jsonify({
            "pqc_library": "available",
            "ml_kem_768": "ML-KEM-768" in algorithms
        })
    except Exception as e:
        return jsonify({
            "pqc_library": "unavailable",
            "error": str(e)
        }), 500

@app.route("/pqc-public-key", methods=["GET"])
def pqc_public_key():
    global cloud_kem, cloud_public_key

    try:
        import oqs

        cloud_kem = oqs.KeyEncapsulation("ML-KEM-768")
        cloud_public_key = cloud_kem.generate_keypair()

        return jsonify({
            "algorithm": "ML-KEM-768",
            "public_key": cloud_public_key.hex()
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/pqc-decapsulate", methods=["POST"])
def pqc_decapsulate():
    global cloud_kem

    try:
        if cloud_kem is None:
            return jsonify({"error": "No active KEM key. Request public key first."}), 400

        from flask import request
        ciphertext = bytes.fromhex(request.json["ciphertext"])

        shared_secret = cloud_kem.decap_secret(ciphertext)

        return jsonify({
            "status": "decapsulation_successful",
            "shared_secret_fingerprint": __import__("hashlib").sha256(
                shared_secret
            ).hexdigest()
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
