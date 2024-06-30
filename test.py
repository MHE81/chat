from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ساخت یک جفت کلید RSA جدید
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=512,
    backend=default_backend()
)
public_key = private_key.public_key()

# سریالیز کردن کلید عمومی به فرمت PEM
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("Generated Public Key:\n", public_key_pem.decode())


# تابعی برای رمزگذاری پیام با استفاده از کلید عمومی
def encrypt_with_public_key(public_key, mess_in_byte: bytes) -> bytes:
    try:
        encrypted = public_key.encrypt(
            mess_in_byte,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted
    except Exception as e:
        print("Encryption failed:", str(e))
        raise


# دریافت پیام از کاربر
message = input("write your message: ")

# اطمینان از اینکه پیام به بایت‌ها تبدیل شده است
try:
    encoded_message = message.encode('utf-8')
    print("پیام به بایت‌ها تبدیل شد:", encoded_message)
except Exception as e:
    print("شکست در تبدیل پیام به بایت‌ها:", str(e))
    raise

# رمزگذاری پیام با استفاده از کلید عمومی جدید
try:
    encrypted_message = encrypt_with_public_key(public_key=public_key, mess_in_byte=encoded_message)
    print("encrypted message", encrypted_message)
except ValueError as e:
    print("شکست در رمزگذاری:", str(e))
    raise
