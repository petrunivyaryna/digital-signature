"""
verify_signature.py

This module verifies the RSA digital signature embedded in an image file.
It extracts the hidden signature and confirms the authenticity and integrity
of the image using a public RSA key.

Typical use case:
    python verify_signature.py

The image must be a PNG file with a 'Signature' field in its metadata.
"""

import base64

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PIL import Image

def load_public_key(path: str = "public_key.pem") -> RSA.RsaKey:
    """
    Load the public RSA key from a PEM file.

    Args:
        path (str): The path to the public key PEM file.

    Returns:
        RSA.RsaKey: The loaded public key.
    """
    with open(path, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())
    return public_key


def verify_signature(image_path: str) -> bool:
    """
    Verify the RSA digital signature embedded in the metadata of a PNG image.

    Args:
        image_path (str): The path to the image file.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    # Opening an image and getting a signature from metadata
    image = Image.open(image_path)
    encoded_signature = image.info.get("Signature")

    if not encoded_signature:
        print("Підпис відсутній.")
        return False

    try:
        signature = base64.b64decode(encoded_signature)
    except base64.binascii.Error as e:
        print("Неможливо декодувати підпис:", e)
        return False

    # Get pixels for hashing
    image_data = image.tobytes()
    hash_obj = SHA256.new(image_data)

    public_key = load_public_key()
    verifier = pkcs1_15.new(public_key)

    try:
        verifier.verify(hash_obj, signature)
        print("Підпис правильний.")
        return True
    except (ValueError, TypeError):
        print("Підпис недійсний.")
        return False

verify_signature("signed_image.png")
