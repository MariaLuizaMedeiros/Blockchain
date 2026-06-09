import hashlib
import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_cifrar(plaintext):
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ct_com_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_com_tag[:-16]
    tag = ct_com_tag[-16:]
    return ciphertext, tag, nonce, aes_key

def aes_decifrar(ciphertext, tag, nonce, aes_key):
    aesgcm = AESGCM(aes_key)
    ct_com_tag = ciphertext + tag
    return aesgcm.decrypt(nonce, ct_com_tag, None)

def rsa_cifrar_chave(aes_key, rsa_pub_destino):
    return rsa_pub_destino.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decifrar_chave(chave_cifrada, rsa_priv):
    return rsa_priv.decrypt(
        chave_cifrada,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def ecdsa_assinar(plaintext, ecdsa_priv):
    hash_msg = hashlib.sha256(plaintext).digest()
    return ecdsa_priv.sign(hash_msg, ec.ECDSA(Prehashed(hashes.SHA256())))

def ecdsa_verificar(plaintext, assinatura, ecdsa_pub):
    try:
        hash_msg = hashlib.sha256(plaintext).digest()
        ecdsa_pub.verify(assinatura, hash_msg, ec.ECDSA(Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False