from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_PATH = Path("secrets") / "aes_key.bin"
KEY_VERSION = 1


def load_key():
    return KEY_PATH.read_bytes()


def decrypt_text(
    encrypted_data,
    table_name,
    column_name,
    emp_id
):
    version = encrypted_data[0]

    if version != KEY_VERSION:
        raise ValueError(
            f"Unsupported key version: {version}"
        )

    nonce = encrypted_data[1:13]
    ciphertext = encrypted_data[13:]

    aad = (
        f"{table_name}.{column_name}:{emp_id}"
    ).encode("utf-8")

    aes = AESGCM(load_key())

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        aad
    )

    return plaintext.decode("utf-8")