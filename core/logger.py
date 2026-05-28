# Classe GerenciadorDeLogs (salvar CSV/banco de dados)

import pandas as pd
import os

class GerenciadorDeLogs:
    def __init__(self, caminho_do_arquivo):
        # Guarda o caminho onde o CSV será salvo
        self.caminho_arquivo = caminho_do_arquivo
        # Inicia a lista vazia na memória do objeto
        self.lista_de_logs = [] 

    def adicionar_registro(self, registro_capturado):
        # Adiciona o dicionário recebido à lista interna do objeto
        self.lista_de_logs.append(registro_capturado)

    def exportar_para_csv(self):
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
            
            # --- DETALHE PARA O HARDWARE (RaspberryPi) ---
            # Limpa a lista da memória após salvar. 
            self.lista_de_logs.clear()