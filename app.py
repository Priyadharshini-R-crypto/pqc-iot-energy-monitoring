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
