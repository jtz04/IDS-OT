"""Parser especifico para MQTT.

O projeto esta evoluindo de Modbus para MQTT, entao este analisador aplica a
mesma ideia do script base: filtrar trafego TCP de uma porta conhecida, validar
se o Scapy reconheceu o protocolo e transformar os campos importantes em log.
"""

from scapy.all import Raw, load_contrib

from core.parsers.base_parser import AnalisadorDeProtocolo

load_contrib("mqtt")

# O Scapy trata MQTT como modulo contrib, por isso carregamos antes de importar.
from scapy.contrib.mqtt import MQTT, MQTTConnect, MQTTPublish, MQTTSubscribe


class AnalisadorMQTT(AnalisadorDeProtocolo):
    """Analisa pacotes MQTT na porta padrao 1883."""

    nome = "MQTT"
    porta = 1883

    def analisar_pacote(self, pkt):
        """Valida e transforma um pacote MQTT em um registro de log."""
        if not self.pacote_usa_porta_do_protocolo(pkt):
            return None

        # Campos de rede sao compartilhados com outros parsers via classe mae.
        dados = self.dados_rede(pkt)

        # Estar na porta 1883 nao garante que o pacote e MQTT valido.
        # Por isso ainda confirmamos se o Scapy conseguiu decodificar a camada.
        if not pkt.haslayer(MQTT):
            print(
                f"[{dados['Horario']}] Pacote TCP na porta {self.porta}, "
                f"mas nao foi decodificado como MQTT: "
                f"{dados['IP_Origem']} -> {dados['IP_Destino']}"
            )
            return None

        camada_mqtt = pkt[MQTT]
        tipo_codigo = camada_mqtt.type
        # O Scapy guarda o mapeamento codigo -> nome no campo type da camada MQTT.
        tipo_mensagem = MQTT.fields_desc[0].i2s.get(tipo_codigo, f"TIPO_{tipo_codigo}")

        # O registro prioriza campos relevantes para IDS: tipo de mensagem,
        # flags, topico, cliente e tamanho do payload.
        registro = {
            **dados,
            "Protocolo": self.nome,
            "Tipo": tipo_mensagem,
            "QoS": camada_mqtt.QOS,
            "Retain": camada_mqtt.RETAIN,
            "Dup": camada_mqtt.DUP,
            "Topico": self._extrair_topico(pkt),
            "Client_ID": self._extrair_client_id(pkt),
            "Tamanho_Payload": self._tamanho_payload(pkt),
        }

        print(
            f"[{dados['Horario']}] Capturado {self.nome}: "
            f"{dados['IP_Origem']} -> {dados['IP_Destino']} | Tipo: {tipo_mensagem}"
        )
        return registro

    def _extrair_topico(self, pkt):
        """Extrai topico de mensagens PUBLISH ou SUBSCRIBE, quando existir."""
        if pkt.haslayer(MQTTPublish):
            return self._normalizar_texto(pkt[MQTTPublish].topic)

        if pkt.haslayer(MQTTSubscribe):
            # Um SUBSCRIBE pode carregar mais de um topico no mesmo pacote.
            topicos = []
            for topico in pkt[MQTTSubscribe].topics:
                valor = getattr(topico, "topic", None)
                if valor:
                    topicos.append(self._normalizar_texto(valor))
            return ",".join(topicos) if topicos else None

        return None

    def _extrair_client_id(self, pkt):
        """Extrai o identificador do cliente em mensagens CONNECT."""
        if pkt.haslayer(MQTTConnect):
            return self._normalizar_texto(pkt[MQTTConnect].clientId)
        return None

    def _tamanho_payload(self, pkt):
        """Calcula o tamanho do payload para ajudar em futuras features de anomalia."""
        if pkt.haslayer(MQTTPublish):
            valor = pkt[MQTTPublish].value
            if valor is None:
                return 0
            if isinstance(valor, str):
                return len(valor.encode())
            return len(bytes(valor))

        if pkt.haslayer(Raw):
            return len(pkt[Raw].load)

        return 0

    def _normalizar_texto(self, valor):
        """Converte bytes/strings do Scapy para texto seguro no CSV."""
        if valor is None:
            return None
        if isinstance(valor, bytes):
            return valor.decode(errors="replace")
        return str(valor)
