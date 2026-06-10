import json
import os
import time
from chaves import *
from chaveiro import *
from mqtt import ClienteMQTT

ORACULO_RSA_PUB = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0JYEsxupPYOio+u8xHdzSNLQgQoPwFx/qceHQJPy2KzNSCXz3FFyKkXaso4UTorzy8XXDv5WkRC1AlDDVu28ANXlrZqLyjLZ8DdplHig2KSxYV5MXA5TyqMDeCAW5CWi+na5Xwr9IbtuTfCv65YeB3QRgZWjZ4oVxpGVek+4dec0qChNl6pL9KmgI4u5CHHC8d7z6MovK0+eN0aMIT2bWgri29tT9sDCoHEGaab1576+SXK3iDXlLkeehJ/h72lqu3HmSL/B5ZE+pKLVLJogSwwMCTejrfTXf5acj9EOq83wGNLTjHIKr2iMz+SZzFS4vxk6qMgltCXjBZfXalzLnwIDAQAB"
ORACULO_ECDSA_PUB = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfmgdDET1IKOR2OxLI9KBBzFB97GyrJKipAuwSrMhDn1w93ieoCb7etbYX5/wrUic9xX5LQbUdgyKSRuCnTPAeQ=="

def carregar_config(caminho="config.json"):
    if os.path.exists(caminho):
        with open(caminho) as f:
            return json.load(f)
    print(f"Arquivo de configuração '{caminho}' não encontrado.")
    exit(1)

def salvar_config(config, caminho="config.json"):
    with open(caminho, "w") as f:
        json.dump(config, f, indent=2)

def inicializar_chaves(config, caminho_config="config.json"):
    minhas = config.get("minhas_chaves", {})
    if minhas.get("rsa_privada") and minhas.get("ecdsa_privada"):
        rsa_priv = carregar_priv_b64(minhas["rsa_privada"])
        rsa_pub = rsa_priv.public_key()
        ecdsa_priv = carregar_priv_b64(minhas["ecdsa_privada"])
        ecdsa_pub = ecdsa_priv.public_key()
    else:
        rsa_priv, rsa_pub = gerar_rsa()
        ecdsa_priv, ecdsa_pub = gerar_ecdsa()
        rsa_exp = export_keys_as_string(rsa_priv, rsa_pub)
        ecdsa_exp = export_keys_as_string(ecdsa_priv, ecdsa_pub)
        config["minhas_chaves"] = {
            "rsa_publica": rsa_exp["public_key"],
            "rsa_privada": rsa_exp["private_key"],
            "ecdsa_publica": ecdsa_exp["public_key"],
            "ecdsa_privada": ecdsa_exp["private_key"]
        }
        salvar_config(config, caminho_config)
    return rsa_priv, rsa_pub, ecdsa_priv, ecdsa_pub

def loop(cliente, gerenciador):
    while True:
        print("1. Enviar mensagem")
        print("2. Listar chaves confiáveis")
        print("3. Revogar unidade")
        print("4. Status da conexão")
        print("5. Enviar echo para o oráculo")
        print("6. Solicitar desafio ao oráculo")
        print("7. Publicar resposta ao oráculo")
        print("8. Atualizar notas")
        print("9. Sair")
        opcao = input("Escolha uma opção: ").strip()
        
        if opcao == "1":
            dest = input("Destinatário: ").strip()
            if not dest:
                print("Destinatário não pode ser vazio.")
                continue
            msg = input("Mensagem: ").strip()
            if not msg:
                print("Mensagem não pode ser vazia.")
                continue
            cliente.enviar_mensagem(dest, msg)
        
        elif opcao == "2":
            chaves = gerenciador.listar()
            if not chaves:
                print("Nenhuma chave registrada.")
            else:
                print(f"Chaves confiáveis ({len(chaves)}):")
                for uid, info in chaves.items():
                    rev = " [REVOGADA]" if uid in cliente.unidades_revogadas else ""
                    print(f"  {uid}{rev}  -  {info.get('ultima_atualizacao', '?')}")
        
        elif opcao == "3":
            unidade = input("ID da unidade a revogar: ").strip().lower()
            if not unidade:
                print("ID inválido.")
                continue
            cliente.unidades_revogadas.add(unidade)
            gerenciador.revogar(unidade)
            cliente.publicar_revogacao(unidade)
            print(f"Unidade {unidade} revogada.")
        
        elif opcao == "4":
            print("MQTT: conectado" if cliente.conectado else "MQTT: desconectado")
        
        elif opcao == "5":
            cliente.enviar_mensagem("oraculo", "hello")
        
        elif opcao == "6":
            cliente.solicitar_desafio_oraculo()
        
        elif opcao == "7":
            conteudo = input("Conteúdo da resposta ao oráculo: ").strip()
            if not conteudo:
                print("Conteúdo não pode ser vazio.")
                continue
            ok = cliente.publicar_resposta_oraculo(conteudo)
            print("Resposta enviada." if ok else "Falha ao enviar resposta.")
        
        elif opcao == "8":
            cliente.atualizar_notas_oraculo()

        elif opcao == "9":
            print("Encerrando...")
            break
        
        else:
            print("Opção inválida. Tente novamente.")

def main():
    config = carregar_config()  # usa 'config.json'
    id_unidade = config.get("id_unidade", "ut-foxtrot").lower()
    rsa_priv, rsa_pub, ecdsa_priv, ecdsa_pub = inicializar_chaves(config)
    gerenciador = Chaveiro(config.get("arquivo_chaves", "chaves_confiaveis.json"))
    unidades_revogadas = set()

    gerenciador.atualizar("oraculo", ORACULO_RSA_PUB, ORACULO_ECDSA_PUB)

    cliente = ClienteMQTT(id_unidade, rsa_priv, rsa_pub, ecdsa_priv, ecdsa_pub, gerenciador, unidades_revogadas, config)
    cliente.conectar()
    time.sleep(1)
    cliente.publicar_chaves()
    loop(cliente, gerenciador)
    cliente.desconectar()

if __name__ == "__main__":
    main()