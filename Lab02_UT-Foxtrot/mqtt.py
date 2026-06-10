import json
import time
from datetime import datetime
import paho.mqtt.client as mqtt
from chaves import load_rsa_pub_key, pub_para_b64
from chaveiro import *
from empacotador import *
from seguranca import (
    log_operacao,
    log_warning,
    log_error,
    log_mensagem_enviada,
    log_mensagem_recebida,
)

TOPIC_CHAVES = "sisdef/broadcast/chaves/{id}"
TOPIC_DIRETO = "sisdef/direto/{id}"
TOPIC_REVOGACAO = "sisdef/broadcast/revogacao"
TOPIC_ORACULO = "sisdef/direto/oraculo"

class ClienteMQTT:
    def __init__(self, id_unidade, rsa_priv, rsa_pub, ecdsa_priv, ecdsa_pub, gerenciador, unidades_revogadas, config):
        self.id_unidade = id_unidade.lower()
        self.rsa_priv = rsa_priv
        self.rsa_pub = rsa_pub
        self.ecdsa_priv = ecdsa_priv
        self.ecdsa_pub = ecdsa_pub
        self.gerenciador = gerenciador
        self.unidades_revogadas = unidades_revogadas
        self.config = config
        self.conectado = False
        self._client = mqtt.Client()
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

    def conectar(self):
        broker = self.config.get("mqtt_broker", "broker.hivemq.com")
        porta = self.config.get("mqtt_port", 1883)
        self._client.connect(broker, porta, keepalive=60)
        self._client.loop_start()
        for _ in range(100):
            if self.conectado:
                break
            time.sleep(0.1)

    def desconectar(self):
        self._client.loop_stop()
        self._client.disconnect()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.conectado = True
            topico_direto = TOPIC_DIRETO.format(id=self.id_unidade)
            client.subscribe("sisdef/broadcast/chaves/+")
            client.subscribe(topico_direto)
            client.subscribe(TOPIC_REVOGACAO)
            client.subscribe("sisdef/broadcast/notas")
            log_operacao(
                "MQTT.connect",
                detalhes=f"id_unidade={self.id_unidade} broker_subscriptions={topico_direto},sisdef/broadcast/chaves/+,sisdef/broadcast/notas,{TOPIC_REVOGACAO}"
            )

    def _on_message(self, client, userdata, msg):
        try:
            topico = msg.topic
            mensagem = msg.payload.decode()
            log_mensagem_recebida(topico, mensagem)
            log_operacao("MQTT.mensagem.recebida", detalhes=f"topico={topico} tamanho={len(mensagem)}")
            if topico.startswith("sisdef/broadcast/chaves/"):
                self._processar_chave_iff(topico, mensagem)
            elif topico == TOPIC_REVOGACAO:
                self._processar_revogacao(mensagem)
            elif topico == TOPIC_DIRETO.format(id=self.id_unidade):
                self._processar_mensagem_segura(mensagem)
        except Exception as erro:
            log_warning(f"MQTT.mensagem.recebida | erro | {erro}")
            pass

    def _on_disconnect(self, client, userdata, rc):
        self.conectado = False

    def publicar_chaves(self):
        if not self.conectado:
            return
        payload = {
            "id_unidade": self.id_unidade,
            "chave_publica_rsa": pub_para_b64(self.rsa_pub),
            "chave_publica_ecdsa": pub_para_b64(self.ecdsa_pub),
            "chave_publica_eddsa": pub_para_b64(self.ecdsa_pub)
        }
        topico = TOPIC_CHAVES.format(id=self.id_unidade)
        log_mensagem_enviada(topico, json.dumps(payload))
        self._client.publish(topico, json.dumps(payload), retain=True)
        log_operacao("MQTT.publicar_chaves", detalhes=f"topico={topico} id_unidade={self.id_unidade}")

    def _processar_chave_iff(self, topico, payload_str):
        try:
            dados = json.loads(payload_str)
            id_ut = dados.get("id_unidade", "").lower()
            if not id_ut:
                log_warning("Chave_iff.processar | mensagem sem id_unidade")
                return
            if id_ut in self.unidades_revogadas:
                log_warning(f"Chave_iff.processar | unidade revogada descartada | id_unidade={id_ut}")
                return
            chave_ecdsa = dados.get("chave_publica_ecdsa") or dados.get("chave_publica_eddsa")
            if chave_ecdsa:
                self.gerenciador.atualizar(id_ut, dados["chave_publica_rsa"], chave_ecdsa)
                log_operacao("Chave_iff.processar", detalhes=f"id_unidade={id_ut}")
        except Exception as erro:
            log_warning(f"Chave_iff.processar | erro | {erro}")
            pass

    def enviar_mensagem(self, destinatario, conteudo):
        if not self.conectado:
            return False
        dest_id = destinatario.lower()
        if dest_id == "oraculo":
            return self._enviar_echo_oraculo()
        info_dest = self.gerenciador.obter(dest_id)
        if not info_dest:
            log_warning(f"Enviar_mensagem | destinatário desconhecido | destinatario={dest_id}")
            return False
        if dest_id in self.unidades_revogadas:
            log_warning(f"Enviar_mensagem | destinatário revogado | destinatario={dest_id}")
            return False
        try:
            rsa_pub_dest = load_rsa_pub_key(info_dest["chave_publica_rsa"])
            plaintext = conteudo.encode("utf-8")
            pacote = montar_pacote_seguro(plaintext, self.id_unidade, rsa_pub_dest, self.ecdsa_priv)
            topico = TOPIC_DIRETO.format(id=dest_id)
            log_mensagem_enviada(topico, json.dumps(pacote))
            self._client.publish(topico, json.dumps(pacote))
            log_operacao("MQTT.enviar_mensagem", detalhes=f"destinatario={dest_id} id_unidade={self.id_unidade}")
            return True
        except Exception as erro:
            log_warning(f"MQTT.enviar_mensagem | erro | destinatario={dest_id} erro={erro}")
            return False

    def _enviar_echo_oraculo(self):
        payload = {"id_unidade": self.id_unidade, "cmd": "echo"}
        log_mensagem_enviada(TOPIC_ORACULO, json.dumps(payload))
        self._client.publish(TOPIC_ORACULO, json.dumps(payload))
        log_operacao("MQTT.enviar_echo_oraculo", detalhes=f"id_unidade={self.id_unidade}")
        return True

    def solicitar_desafio_oraculo(self):
        if not self.conectado:
            print("Erro: Não conectado ao broker MQTT.")
            log_warning("Solicitar_desafio_oraculo | falha | desconectado")
            return False
        payload = {"id_unidade": self.id_unidade, "cmd": "desafio"}
        log_mensagem_enviada(TOPIC_ORACULO, json.dumps(payload))
        self._client.publish(TOPIC_ORACULO, json.dumps(payload))
        log_operacao("MQTT.solicitar_desafio_oraculo", detalhes=f"id_unidade={self.id_unidade}")
        print("Solicitação de desafio enviada ao Oráculo!")
        return True

    def _processar_mensagem_segura(self, payload_str):
        try:
            pacote = json.loads(payload_str)
        except Exception as erro:
            log_warning(f"Processar_mensagem_segura | inválido | erro_json={erro}")
            return
        plaintext = validar_pacote(pacote, self.rsa_priv, self.gerenciador.todas(), self.unidades_revogadas)
        
        try:
            id_unidade = pacote["id_unidade"]
        except Exception:
            log_warning("Processar_mensagem_segura | inválido | id_unidade ausente")
            return
        
        if plaintext is not None:
            log_operacao("Processar_mensagem_segura", detalhes=f"id_unidade={id_unidade}")
            print(f"\n Mensagem válida de {id_unidade}")
            print(plaintext.decode("utf-8", errors="replace"))
        else:
            log_warning(f"Processar_mensagem_segura | inválido | id_unidade={id_unidade}")
            self._reportar_erro_oraculo(f"Mensagem inválida de {id_unidade}")

    def _reportar_erro_oraculo(self, motivo):
        info_oraculo = self.gerenciador.obter("oraculo")
        if not info_oraculo:
            log_warning("Reportar_erro_oraculo | oraculo não encontrado")
            return
        try:
            rsa_pub_oraculo = load_rsa_pub_key(info_oraculo["chave_publica_rsa"])
            pacote = montar_pacote_seguro(motivo.encode("utf-8"), self.id_unidade, rsa_pub_oraculo, self.ecdsa_priv)
            log_mensagem_enviada(TOPIC_ORACULO, json.dumps(pacote))
            self._client.publish(TOPIC_ORACULO, json.dumps(pacote))
            log_operacao("Reportar_erro_oraculo", detalhes=f"motivo={motivo}")
        except Exception as erro:
            log_warning(f"Reportar_erro_oraculo | erro | {erro}")
            pass

    def publicar_revogacao(self, unidade):
        if not self.conectado:
            log_warning(f"Publicar_revogacao | falha | desconectado unidade={unidade}")
            return False
        try:
            pacote = montar_pacote_revogacao(unidade, self.id_unidade, self.ecdsa_priv)
            log_mensagem_enviada(TOPIC_REVOGACAO, json.dumps(pacote))
            self._client.publish(TOPIC_REVOGACAO, json.dumps(pacote))
            log_operacao("MQTT.publicar_revogacao", detalhes=f"unidade={unidade} remetente={self.id_unidade}")
            return True
        except Exception as erro:
            log_warning(f"Publicar_revogacao | erro | unidade={unidade} erro={erro}")
            return False

    def _processar_revogacao(self, payload_str):
        try:
            pacote = json.loads(payload_str)
        except Exception as erro:
            log_warning(f"Processar_revogacao | JSON inválido | erro={erro}")
            return
        unidade_revogada = validar_revogacao(pacote, self.gerenciador.todas())
        if unidade_revogada:
            self.unidades_revogadas.add(unidade_revogada)
            self.gerenciador.revogar(unidade_revogada)
            log_operacao("Processar_revogacao", detalhes=f"unidade_revogada={unidade_revogada}")

    def publicar_resposta_oraculo(self, conteudo):
        """Publica um pacote seguro para o oráculo contendo cmd:'resposta'."""
        if not self.conectado:
            log_warning("Publicar_resposta_oraculo | falha | desconectado")
            return False
        info_oraculo = self.gerenciador.obter("oraculo")
        if not info_oraculo:
            log_warning("Publicar_resposta_oraculo | falha | oraculo não encontrado")
            return False
        try:
            rsa_pub_oraculo = load_rsa_pub_key(info_oraculo["chave_publica_rsa"])
            plaintext = conteudo.encode("utf-8")
            pacote = montar_pacote_seguro(plaintext, self.id_unidade, rsa_pub_oraculo, self.ecdsa_priv)
            pacote["cmd"] = "resposta"
            log_mensagem_enviada(TOPIC_ORACULO, json.dumps(pacote))
            self._client.publish(TOPIC_ORACULO, json.dumps(pacote))
            log_operacao("MQTT.publicar_resposta_oraculo", detalhes=f"id_unidade={self.id_unidade}")
            return True
        except Exception as erro:
            log_warning(f"Publicar_resposta_oraculo | erro | {erro}")
            return False
        
    def atualizar_notas_oraculo(self):
        if not self.conectado:
            print("Erro: Não conectado ao broker MQTT.")
            log_warning("Atualizar_notas_oraculo | falha | desconectado")
            return False
        payload = {"cmd": "atualizar_notas"}
        log_mensagem_enviada(TOPIC_ORACULO, json.dumps(payload))
        self._client.publish(TOPIC_ORACULO, json.dumps(payload), retain=False)
        log_operacao("MQTT.atualizar_notas_oraculo", detalhes=f"id_unidade={self.id_unidade}")
        print("Solicitação de atualização de notas enviada ao Oráculo!")
        return True