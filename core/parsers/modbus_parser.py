"""Parser especifico para Modbus TCP.

Este arquivo guarda as regras que eram feitas diretamente no `scriptbase.py`.
Ao transformar em classe, a logica Modbus fica isolada e pode conviver com MQTT
sem que o sniffer precise saber como cada protocolo e interpretado.
"""

from scapy.all import load_contrib

from core.parsers.base_parser import AnalisadorDeProtocolo

load_contrib("modbus")

# O import fica depois do load_contrib porque o Scapy registra as camadas
# Modbus como modulo contrib antes de expor as classes usadas abaixo.
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse


class AnalisadorModbus(AnalisadorDeProtocolo):
    """Analisa pacotes Modbus TCP na porta padrao 502."""

    nome = "Modbus TCP"
    porta = 502

    def analisar_pacote(self, pkt):
        """Valida e transforma um pacote Modbus em um registro de log."""
        if not self.pacote_usa_porta_do_protocolo(pkt):
            return None

        # Estes campos sao comuns e vem da classe mae para manter padrao no CSV.
        dados = self.dados_rede(pkt)
        tipo = None
        codigo_funcao = None

        # Modbus TCP usa ADU para encapsular requisicoes e respostas.
        # A direcao e inferida pela camada que o Scapy reconheceu no pacote.
        if pkt.haslayer(ModbusADURequest):
            tipo = "Request"
            codigo_funcao = self._extrair_codigo_funcao(pkt[ModbusADURequest])
        elif pkt.haslayer(ModbusADUResponse):
            tipo = "Response"
            codigo_funcao = self._extrair_codigo_funcao(pkt[ModbusADUResponse])
        else:
            print(
                f"[{dados['Horario']}] Pacote TCP na porta {self.porta}, "
                f"mas nao e Modbus valido: {dados['IP_Origem']} -> {dados['IP_Destino']}"
            )
            return None

        # Sem codigo de funcao nao ha informacao util para o IDS neste registro.
        if codigo_funcao is None:
            print(
                f"[{dados['Horario']}] Pacote Modbus sem PDU reconhecida: "
                f"{dados['IP_Origem']} -> {dados['IP_Destino']}"
            )
            return None

        # O formato do dicionario segue o mesmo principio do script base,
        # mas adiciona o nome do protocolo para facilitar datasets mistos.
        registro = {
            **dados,
            "Protocolo": self.nome,
            "Tipo": tipo,
            "Funcao": codigo_funcao,
        }

        print(
            f"[{dados['Horario']}] Capturado {self.nome}: "
            f"{dados['IP_Origem']} -> {dados['IP_Destino']} | Funcao: {codigo_funcao}"
        )
        return registro

    def _extrair_codigo_funcao(self, camada_adu):
        """Procura o funcCode nas camadas internas do pacote Modbus."""
        camada_atual = camada_adu
        while camada_atual:
            # Em alguns pacotes o funcCode nao fica diretamente na ADU,
            # mas sim na PDU que vem como payload. Por isso percorremos a pilha.
            if hasattr(camada_atual, "funcCode"):
                return camada_atual.funcCode
            camada_atual = camada_atual.payload
            if camada_atual is None or camada_atual.__class__.__name__ == "NoPayload":
                break
        return None
