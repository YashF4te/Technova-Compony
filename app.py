import os
import time
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
from crypto_utils import FileCrypto
import config

app = Flask(__name__)
crypto = FileCrypto(config.SFTS_MASTER_KEY)

# Simple API-key check (replace with real IAM/MFA in production)
def check_api_key(req):
    key = req.headers.get("X-API-KEY")
    return key == config.SFTS_API_KEY

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": int(time.time())})

@app.route("/upload", methods=["POST"])
def upload():
    if not check_api_key(request):
        return jsonify({"error": "unauthorized"}), 401

    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    f = request.files["file"]
    filename = secure_filename(f.filename)
    if filename == "":
        return jsonify({"error": "invalid filename"}), 400

    data = f.read()
    # Optionally include metadata (filename, uploader id) as associated_data to bind
    associated = filename.encode()

    enc = crypto.encrypt(data, associated_data=associated)
    out_path = os.path.join(config.UPLOAD_DIR, filename + ".enc")
    with open(out_path, "wb") as fh:
        fh.write(enc)

    return jsonify({"message": "uploaded", "stored_as": out_path})

@app.route("/download/<path:filename>", methods=["GET"])
def download(filename):
    if not check_api_key(request):
        return jsonify({"error": "unauthorized"}), 401

    # expect client asks for decrypted file by name
    enc_path = os.path.join(config.UPLOAD_DIR, secure_filename(filename) + ".enc")
    if not os.path.exists(enc_path):
        return jsonify({"error": "not found"}), 404

    with open(enc_path, "rb") as fh:
        enc = fh.read()

    associated = filename.encode()
    plaintext = crypto.decrypt(enc, associated_data=associated)

    # create a temporary send file
    from io import BytesIO
    bio = BytesIO(plaintext)
    bio.seek(0)
    return send_file(bio, download_name=filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
