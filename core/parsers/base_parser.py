"""Interface base para parsers de protocolos.

O objetivo desta classe mae e padronizar o que todo analisador precisa oferecer:
porta, filtro BPF, validacao basica TCP/IP e metodo `analisar_pacote`. Assim,
Modbus e MQTT podem ter regras diferentes sem mudar o restante do sistema.
"""

from abc import ABC, abstractmethod
from datetime import datetime

from scapy.all import IP, TCP


class AnalisadorDeProtocolo(ABC):
    """Interface comum para analisadores de protocolos industriais/IoT."""

    # Classes filhas sobrescrevem estes atributos para indicar o protocolo real.
    nome = "generico"
    porta = None

    def __init__(self, porta=None):
        # Permite alterar a porta em testes ou ambientes especiais sem criar outra classe.
        if porta is not None:
            self.porta = porta

    @property
    def filtro_bpf(self):
        """Filtro usado pelo Scapy para capturar apenas a porta do protocolo."""
        return f"tcp port {self.porta}"

    def pacote_usa_porta_do_protocolo(self, pkt):
        """Confere se o pacote tem IP/TCP e se origem ou destino usa a porta monitorada."""
        return (
            pkt.haslayer(IP)
            and pkt.haslayer(TCP)
            and (pkt[TCP].dport == self.porta or pkt[TCP].sport == self.porta)
        )

    def dados_rede(self, pkt):
        """Extrai campos comuns a todos os protocolos analisados."""
        return {
            "Horario": datetime.fromtimestamp(pkt.time).strftime("%Y-%m-%d %H:%M:%S"),
            "IP_Origem": pkt[IP].src,
            "IP_Destino": pkt[IP].dst,
        }

    @abstractmethod
    def analisar_pacote(self, pkt):
        """Retorna um dicionario de log quando o pacote for valido."""
