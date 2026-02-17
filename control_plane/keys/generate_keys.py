from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Gera chave privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Exporta privada
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

# Exporta pública
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open("jwt_private.pem", "wb") as f:
    f.write(private_pem)

with open("jwt_public.pem", "wb") as f:
    f.write(public_pem)

print("Chaves geradas com sucesso!")
