
from flask import Flask, jsonify

app = Flask(__name__)

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
    try:
        import oqs

        kem = oqs.KeyEncapsulation("ML-KEM-768")
        public_key = kem.generate_keypair()

        return jsonify({
            "algorithm": "ML-KEM-768",
            "public_key": public_key.hex()
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
