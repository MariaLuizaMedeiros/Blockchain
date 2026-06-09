import json
import os
import threading
from datetime import datetime, timezone

class Chaveiro:
    def __init__(self, arquivo="chaves_confiaveis.json"):
        self.arquivo = arquivo
        self._lock = threading.Lock()
        self.chaves = self._carregar()

    def _carregar(self):
        if os.path.exists(self.arquivo):
            try:
                with open(self.arquivo, "r") as f:
                    dados = json.load(f)
                return dados
            except Exception:
                pass
        return {}

    def _salvar(self):
        try:
            with open(self.arquivo, "w") as f:
                json.dump(self.chaves, f, indent=2)
        except Exception:
            pass

    def atualizar(self, id_unidade, chave_rsa_b64, chave_ecdsa_b64):
        with self._lock:
            self.chaves[id_unidade.lower()] = {
                "chave_publica_rsa": chave_rsa_b64,
                "chave_publica_ecdsa": chave_ecdsa_b64,
                "ultima_atualizacao": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            self._salvar()

    def revogar(self, id_unidade):
        with self._lock:
            if id_unidade.lower() in self.chaves:
                del self.chaves[id_unidade.lower()]
                self._salvar()

    def obter(self, id_unidade):
        return self.chaves.get(id_unidade.lower())

    def listar(self):
        return dict(self.chaves)

    def todas(self):
        return self.chaves