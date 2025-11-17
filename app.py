import streamlit as st
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ===========================================================
# CONFIG (you can edit the key anytime)
# ===========================================================
MASTER_KEY = AESGCM.generate_key(bit_length=256)  # 32-byte AES key
UPLOAD_DIR = "uploads"

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ===========================================================
# ENCRYPTION / DECRYPTION UTILITIES
# ===========================================================
class FileCrypto:
    def __init__(self, key: bytes):
        self.key = key
        self.aes = AESGCM(key)

    def encrypt(self, data: bytes, associated_data: bytes = b""):
        nonce = os.urandom(12)  # AES-GCM nonce
        ct = self.aes.encrypt(nonce, data, associated_data)
        return nonce + ct  # prepend nonce

    def decrypt(self, blob: bytes, associated_data: bytes = b""):
        nonce = blob[:12]
        ct = blob[12:]
        return self.aes.decrypt(nonce, ct, associated_data)


crypto = FileCrypto(MASTER_KEY)

# ===========================================================
# STREAMLIT UI
# ===========================================================
st.set_page_config(page_title="Secure File Transfer System", layout="centered")

st.title("🔐 Secure File Transfer System")
st.write("Upload files to encrypt and download them securely. Decrypt .enc files to recover originals.")

st.info(f"**Your encryption key (auto-generated):** `"
        f"{base64.b64encode(MASTER_KEY).decode()}`")

# ===========================================================
# UPLOAD + ENCRYPT
# ===========================================================
st.header("📤 Upload & Encrypt File")

uploaded = st.file_uploader("Select any file to encrypt")

if uploaded:
    filename = uploaded.name
    data = uploaded.read()

    associated = filename.encode()
    encrypted = crypto.encrypt(data, associated_data=associated)

    # Save encrypted file
    encrypted_path = os.path.join(UPLOAD_DIR, filename + ".enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted)

    st.success(f"Encrypted file saved as: {encrypted_path}")

    st.download_button(
        label="⬇ Download Encrypted File",
        data=encrypted,
        file_name=filename + ".enc",
        mime="application/octet-stream"
    )

# ===========================================================
# DECRYPT .ENC FILE
# ===========================================================
st.header("🔐 Decrypt File (.enc)")

enc_file = st.file_uploader("Select an encrypted (.enc) file", type=["enc"])

if enc_file:
    enc_filename = enc_file.name

    # guess original name
    orig_name = enc_filename[:-4] if enc_filename.endswith(".enc") else "decrypted_file"

    encrypted_data = enc_file.read()
    associated = orig_name.encode()

    try:
        decrypted = crypto.decrypt(encrypted_data, associated_data=associated)
        st.success("File decrypted successfully!")

        st.download_button(
            label="⬇ Download Decrypted File",
            data=decrypted,
            file_name=orig_name,
            mime="application/octet-stream"
        )
    except Exception as e:
        st.error("❌ Decryption failed — wrong key, damaged file, or filename mismatch.")
