import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from chaves import *
from cripto import *
from seguranca import operacao as log_operacao, warning as log_warning, error as log_error

def montar_pacote_seguro(plaintext, id_unidade, rsa_pub_destino, ecdsa_priv_remetente):
    assinatura = ecdsa_assinar(plaintext, ecdsa_priv_remetente)
    ciphertext, tag, nonce, aes_key = aes_cifrar(plaintext)
    chave_sessao_cifrada = rsa_cifrar_chave(aes_key, rsa_pub_destino)
    log_operacao("Pacote.seguro.montar", detalhes=f"id_unidade={id_unidade}")
    return {
        "id_unidade": id_unidade,
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "tag_autenticacao_b64": base64.b64encode(tag).decode(),
        "nonce_b64": base64.b64encode(nonce).decode(),
        "chave_sessao_cifrada_b64": base64.b64encode(chave_sessao_cifrada).decode(),
        "assinatura_b64": base64.b64encode(assinatura).decode()
    }
    
def validar_pacote(pacote, rsa_priv_receptor, chaves_confiaveis, unidades_revogadas):
    try:
        id_unidade = pacote.get("id_unidade", "").lower()
        
        if id_unidade in unidades_revogadas:
            raise Exception(f"Mensagem de unidade revogada '{id_unidade}' descartada")

        if id_unidade not in chaves_confiaveis:
            raise Exception(f"Remetente desconhecido '{id_unidade}'")

        ciphertext = base64.b64decode(pacote["ciphertext_b64"])
        tag = base64.b64decode(pacote["tag_autenticacao_b64"])
        nonce = base64.b64decode(pacote["nonce_b64"])
        chave_sessao_cifrada = base64.b64decode(pacote["chave_sessao_cifrada_b64"])
        assinatura = base64.b64decode(pacote["assinatura_b64"])
        aes_key = rsa_decifrar_chave(chave_sessao_cifrada, rsa_priv_receptor)
        plaintext = aes_decifrar(ciphertext,tag,nonce,aes_key)
        info = chaves_confiaveis[id_unidade]
        ecdsa_pub = load_ecdsa_pub_key(info["chave_publica_ecdsa"])

        if not ecdsa_verificar(plaintext, assinatura, ecdsa_pub):
            raise Exception(
                f"Assinatura inválida de '{id_unidade}'"
            )

        log_operacao("Pacote.seguro.validar", detalhes=f"id_unidade={id_unidade}")
        print(f"Mensagem de {id_unidade}")
        return plaintext

    except Exception as erro:
        log_warning(f"Pacote.seguro.validar | falha | {erro}")
        print(f"Erro na validação: {erro}")
        return None


def montar_pacote_revogacao(unidade_revogada, id_remetente, ecdsa_priv):
    try:
        revogacao = {
            "unidade_revogada": unidade_revogada.lower(),
            "timestamp": datetime.now(
                timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
        }

        payload_bytes = json.dumps(revogacao, separators=(",", ":"), sort_keys=True).encode("utf-8")
        hash_rev = hashlib.sha256(payload_bytes).digest()
        assinatura = ecdsa_priv.sign(hash_rev, ec.ECDSA(Prehashed(hashes.SHA256())))

        log_operacao("Revogacao.montar", detalhes=f"unidade_revogada={unidade_revogada.lower()} remetente={id_remetente}")
        return {
            "remetente": id_remetente,
            "revogacao": revogacao,
            "assinatura_b64": base64.b64encode(
                assinatura
            ).decode()
        }

    except Exception as erro:
        log_error(f"Revogacao.montar | erro | {erro}")
        print(f"Erro ao montar pacote de revogação: {erro}")
        return None


def validar_revogacao(pacote, chaves_confiaveis):
    try:
        remetente = pacote.get(
            "remetente",
            ""
        ).lower()

        if remetente not in chaves_confiaveis:
            raise Exception(
                f"Revogação de remetente desconhecido '{remetente}'"
            )

        revogacao = pacote["revogacao"]
        assinatura = base64.b64decode(pacote["assinatura_b64"])
        payload_bytes = json.dumps(revogacao, separators=(",", ":"), sort_keys=True).encode("utf-8")
        hash_rev = hashlib.sha256(payload_bytes).digest()
        info = chaves_confiaveis[remetente]
        ecdsa_pub = load_ecdsa_pub_key(info["chave_publica_ecdsa"])
        ecdsa_pub.verify( assinatura, hash_rev, ec.ECDSA(Prehashed(hashes.SHA256())))
        log_operacao("Revogacao.validar", detalhes=f"remetente={remetente} unidade_revogada={revogacao['unidade_revogada']}")
        print("Revogação válida")
        return revogacao["unidade_revogada"]

    except Exception as erro:
        log_warning(f"Revogacao.validar | falha | {erro}")
        print( f"Erro na validação da revogação: {erro}")
        return None