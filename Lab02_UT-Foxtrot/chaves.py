import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# Detalhe: algumas funções foram reaproveitadas do lab do professor
def gerar_rsa():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def gerar_ecdsa():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()

def export_keys_as_string(private_key, public_key):
    _priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    _pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    chaves = {
        "private_key": base64.b64encode(_priv_bytes).decode(),
        "public_key": base64.b64encode(_pub_bytes).decode()
    }
    return chaves

def load_rsa_pub_key(b64_str):
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_public_key(key_bytes)

def load_ecdsa_pub_key(b64_str):
    key_bytes = base64.b64decode(b64_str)
    return serialization.load_der_public_key(key_bytes)

def pub_para_b64(public_key):
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(raw).decode()

def priv_para_b64(private_key):
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return base64.b64encode(raw).decode()

def carregar_priv_b64(b64_str):
    return serialization.load_der_private_key(base64.b64decode(b64_str), password=None)