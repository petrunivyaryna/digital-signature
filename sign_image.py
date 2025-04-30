"""
sign_image.py

This module performs RSA digital signing of a PNG image.
The signature is computed over the raw pixel data and stored
in the image's metadata in base64 format.

Typical usage:
    python sign_image.py

The resulting signed image will be saved as 'signed_<original_filename>.png'.
"""

import base64

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PIL import Image, PngImagePlugin

def load_private_key(path: str = "private_key.pem") -> RSA.RsaKey:
    """
    Load the RSA private key from a PEM file.

    Args:
        path (str): Path to the private key file.

    Returns:
        RSA.RsaKey: The loaded private key.
    """
    with open(path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())
    return private_key


def sign_image(image_path: str) -> str:
    """
    Sign the image by adding a digital RSA signature to its PNG metadata.

    The signature is computed from the pixel byte content of the image.

    Args:
        image_path (str): Path to the PNG image to be signed.

    Returns:
        str: Path to the newly signed image.
    """
    # Download the image
    image = Image.open(image_path)
    image_data = image.tobytes()

    # Hashing pixel content
    hash_obj = SHA256.new(image_data)

    # Creating a signature using a private key
    private_key = load_private_key()
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(hash_obj)

    # Encoding signature in base64 to store in metadata
    encoded_signature = base64.b64encode(signature).decode('utf-8')

    # Add a signature to png metadata
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Signature", encoded_signature)

    # Saving the image
    signed_image_path = "signed_" + image_path
    image.save(signed_image_path, "PNG", pnginfo=meta)

    print(f"Підписане зображення збережене як: {signed_image_path}")
    return signed_image_path

sign_image("image.png")
