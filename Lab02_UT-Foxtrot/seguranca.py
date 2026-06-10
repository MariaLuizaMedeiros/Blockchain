import os
from datetime import datetime

LOG_DIR = "logs"
SECURITY_LOG = os.path.join(LOG_DIR, "seguranca.log")
MENSAGEM_ENVIADA_LOG = os.path.join(LOG_DIR, "enviadas_mensagens.log")
MENSAGEM_RECEBIDA_LOG = os.path.join(LOG_DIR, "todas_mensagens.log")

os.makedirs(LOG_DIR, exist_ok=True)


def _timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _append_to_file(path, content):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass


def _format_security_entry(level, message):
    return f"[{_timestamp()}] {level} {message}\n"


def info(message):
    _append_to_file(SECURITY_LOG, _format_security_entry("INFO", message))


def warning(message):
    _append_to_file(SECURITY_LOG, _format_security_entry("WARNING", message))


def error(message):
    _append_to_file(SECURITY_LOG, _format_security_entry("ERROR", message))


def operacao(nome, resultado="OK", detalhes=None):
    if detalhes:
        mensagem = f"{nome} | {resultado} | {detalhes}"
    else:
        mensagem = f"{nome} | {resultado}"
    _append_to_file(SECURITY_LOG, _format_security_entry("INFO", mensagem))


def log_mensagem_enviada(topico, mensagem):
    try:
        content = f"[{_timestamp()}] Tópico: {topico}\nMensagem: {mensagem}\n{'-' * 80}\n"
        _append_to_file(MENSAGEM_ENVIADA_LOG, content)
    except Exception:
        pass


def log_mensagem_recebida(topico, mensagem):
    try:
        content = f"[{_timestamp()}] Tópico: {topico}\nMensagem: {mensagem}\n{'-' * 80}\n"
        _append_to_file(MENSAGEM_RECEBIDA_LOG, content)
    except Exception:
        pass
