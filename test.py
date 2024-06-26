import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def rsa_sign_with_private_key(private_key, message):
    signature = private_key.sign(
        message.encode('utf-8'),  # Convert message to bytes
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def rsa_verify_with_public_key(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),  # Convert message to bytes
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Example usage:
def test_rsa_sign_and_verify():
    # Generate RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Sign message with private key
    message = "Hello, this is a secret message!"
    signature = rsa_sign_with_private_key(private_key, message)
    print("Signature (Base64):\n", base64.b64encode(signature).decode('utf-8'))

    # Verify signature with public key
    is_verified = rsa_verify_with_public_key(public_key, message, signature)
    if is_verified:
        print("Signature verified successfully.")
    else:
        print("Signature verification failed.")

test_rsa_sign_and_verify()
