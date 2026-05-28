# script utilizado como base para passar para logica de POO e organizar o código em classes e métodos

import os
import pandas as pd
from scapy.all import TCP, IP, sniff, load_contrib
from datetime import datetime

# carregar o modulo de protocolo modbus para que o scapy possa reconhecer os pacotes modbus
load_contrib('modbus')

# importar as classes de request e response do modbus para analisar os pacotes
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse

# lista para armazenar os logs dos pacotes capturados
logs_ids = []

# função para analisar os pacotes capturados
def analisa_pkt_modbus(pkt):
    # checagem de seguranca para verificar se o pacote tem a camada IP e TCP
    if pkt.haslayer(IP) and pkt[TCP]:

        # checagem para verificar se o pacote é do Modbus TCP (porta 502)
        if pkt[TCP].dport == 502 or pkt[TCP].sport == 502:

            # extrair IPs
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Converte o horário do pacote (timestamp) para algo legível
            horario = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')

            tipo = None
            codigo_funcao = None
            is_modbus_valid = False  # Flag para indicar se é um pacote Modbus válido

            # identificar se é uma requisicao ou resposta do Modbus
            
            if pkt.haslayer(ModbusADURequest):
                tipo = "Request"
                codigo_funcao = pkt[ModbusADURequest].funcCode
                is_modbus_valid = True
            elif pkt.haslayer(ModbusADUResponse):
                tipo = "Response"
                codigo_funcao = pkt[ModbusADUResponse].funcCode
                is_modbus_valid = True
            else:
                print(f"[{horario}] Pacote TCP na porta 502, mas não é Modbus válido: {src_ip} -> {dst_ip}")

            # Criar e salvar registro apenas se for Modbus válido
            if is_modbus_valid:
                registro = {
                    "Horario": horario,
                    "IP_Origem": src_ip,
                    "IP_Destino": dst_ip,
                    "Tipo": tipo,
                    "Funcao": codigo_funcao
                }
                logs_ids.append(registro)
                print(f"[{horario}] Capturado: {src_ip} -> {dst_ip} | Funcao: {codigo_funcao}")
            
        print("Pacote Modbus TCP detectado:")

        # exibir um resumo do pacote
        print(pkt.summary())

# numero de pacotes 
# ... (mantenha todos os seus imports e a função analisa_pkt_modbus iguais) ...

print("---- Iniciando sensor IDS na rede virtual: ----")
print("Aguardando trafego na porta 502...")
print("Pressione Ctrl+C para interromper a captura e gerar o CSV.\n")

try:
    # Mudança 1 e Filtro mais limpo: Escutando a interface eth0 do container
    # Opcional: Adicionado 'and host 172.20.0.10' no filtro para pegar só tráfego do Scada
    sniff(iface="eth0", filter="tcp port 502 and host 172.20.0.10", prn=analisa_pkt_modbus)
    
except KeyboardInterrupt:
    # O script cai aqui quando você aperta Ctrl+C
    print("\n--- Captura interrompida pelo usuário. ---")

# tratamento dos logs capturados para salvar em um arquivo CSV e exibir a tabela final
print("Gerando DataFrame...")

# Mudança 2: Caminho absoluto apontando para o volume mapeado para o Windows
csv_file = "/app/logs_modbus.csv" 
df_logs = pd.DataFrame(logs_ids)

if df_logs.empty:
    print("Nenhum log Modbus válido capturado. O arquivo CSV não foi alterado.")
else:
    write_header = not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0
    df_logs.to_csv(csv_file, sep=";", index=False, mode="a", header=write_header)
    print(f"Logs salvos com sucesso em '{csv_file}'. (Você já pode abrir no Windows!)")

print("\nTabela final de Logs (Amostra):")
print(df_logs.head(15).to_string()) # Exibe apenas os primeiros 15 no terminal para não travar