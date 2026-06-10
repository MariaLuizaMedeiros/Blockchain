import json
import os
import threading
from datetime import datetime, timezone
from seguranca import operacao as log_operacao, warning as log_warning

class Chaveiro:
    def __init__(self, arquivo):
        self.arquivo = arquivo
        self._lock = threading.Lock()
        self.chaves = self._carregar()

    def _carregar(self):
        dados = {}
        if os.path.exists(self.arquivo):
            with open(self.arquivo, "r") as f:
                dados = json.load(f)
        return dados

    def _salvar(self):
        with open(self.arquivo, "w") as f:
            json.dump(self.chaves, f, indent=2)

    def atualizar(self, id_unidade, chave_rsa_b64, chave_ecdsa_b64):
        with self._lock:
            uid = id_unidade.lower()
            self.chaves[uid] = {
                "chave_publica_rsa": chave_rsa_b64,
                "chave_publica_ecdsa": chave_ecdsa_b64,
                "ultima_atualizacao": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            self._salvar()
            log_operacao("Chaveiro.atualizar", detalhes=f"id_unidade={uid}")

    def revogar(self, id_unidade):
        with self._lock:
            uid = id_unidade.lower()
            if uid in self.chaves:
                del self.chaves[uid]
                self._salvar()
                log_operacao("Chaveiro.revogar", detalhes=f"id_unidade={uid}")
            else:
                log_warning(f"Chaveiro.revogar | unidade não encontrada | id_unidade={uid}")

    def obter(self, id_unidade):
        return self.chaves.get(id_unidade.lower())

    def listar(self):
        return dict(self.chaves)

    def todas(self):
        return self.chaves