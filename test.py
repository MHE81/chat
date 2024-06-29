from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ایجاد کلید خصوصی
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# استخراج کلید عمومی از کلید خصوصی
public_key = private_key.public_key()

# ذخیره کلید خصوصی به صورت PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private_key.pem', 'wb') as f:
    f.write(private_pem)

# ذخیره کلید عمومی به صورت PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open('public_key.pem', 'wb') as f:
    f.write(public_pem)

print("Keys have been generated and saved.")
