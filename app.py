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
