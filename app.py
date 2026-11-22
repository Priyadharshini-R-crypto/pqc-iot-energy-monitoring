
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
