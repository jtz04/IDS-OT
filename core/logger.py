"""Gerenciamento dos logs capturados pelo IDS.

Este modulo separa a persistencia dos dados da captura de rede. A escolha foi
feita para permitir trocar CSV por banco de dados no futuro sem alterar o
sniffer nem os parsers de protocolo.
"""

import pandas as pd
import os

class GerenciadorDeLogs:
    """Armazena registros em memoria e exporta para CSV."""

    def __init__(self, caminho_do_arquivo):
        # Guarda o caminho onde o CSV será salvo
        self.caminho_arquivo = caminho_do_arquivo
        # Inicia a lista vazia na memória do objeto
        self.lista_de_logs = [] 

    def adicionar_registro(self, registro_capturado):
        # Adiciona o dicionário recebido à lista interna do objeto
        # Cada registro ja vem padronizado pelo parser do protocolo.
        self.lista_de_logs.append(registro_capturado)

    def exportar_para_csv(self):
        """Transforma os registros acumulados em tabela e salva no disco."""
        print("\nProcessando exportação de logs...")
        
        # O Pandas transforma a lista interna do objeto em uma tabela
        df_logs = pd.DataFrame(self.lista_de_logs)

        if df_logs.empty:
            print("Nenhum log válido na memória. O arquivo CSV não foi alterado.")
        else:
            # Verifica se o arquivo já existe e tem tamanho maior que 0 para decidir se escreve o cabeçalho
            write_header = not os.path.exists(self.caminho_arquivo) or os.path.getsize(self.caminho_arquivo) == 0
            
            # Salva no disco (modo "a" faz o append, ou seja, adiciona no final do arquivo sem apagar o que já tem)
            df_logs.to_csv(self.caminho_arquivo, sep=";", index=False, mode="a", header=write_header)
            
            print(f"[{len(self.lista_de_logs)}] Logs salvos com sucesso em '{self.caminho_arquivo}'.")
            print("\nTabela final de Logs (Amostra):")
            print(df_logs.head(15).to_string())
            
            # --- DETALHE PARA O HARDWARE (RaspberryPi) ---
            # Limpa a lista da memória após salvar. 
            self.lista_de_logs.clear()
