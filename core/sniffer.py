"""Captura bruta de pacotes de rede.

A classe `RedeSniffer` nao conhece detalhes de Modbus ou MQTT. Ela apenas usa
um analisador recebido por parametro. Essa escolha aplica composicao: o mesmo
sniffer pode trabalhar com qualquer protocolo que siga a interface definida em
`AnalisadorDeProtocolo`.
"""

from scapy.all import sniff


class RedeSniffer:
    """Coordena a captura Scapy e envia cada pacote ao analisador configurado."""

    def __init__(self, analisador, gerenciador_logs, interface="eth0", host=None, limite_pacotes=0):
        # Receber as dependencias no construtor deixa a classe reutilizavel.
        # Ela nao precisa criar parser nem logger por conta propria.
        self.analisador = analisador
        self.gerenciador_logs = gerenciador_logs
        self.interface = interface
        self.host = host
        self.limite_pacotes = limite_pacotes

    def iniciar(self):
        """Inicia a captura e garante a exportacao dos logs ao final."""
        filtro = self._montar_filtro()

        print("---- Iniciando sensor IDS na rede virtual ----")
        print(f"Protocolo monitorado: {self.analisador.nome}")
        print(f"Interface: {self.interface}")
        print(f"Filtro BPF: {filtro}")
        print("Pressione Ctrl+C para interromper a captura e gerar o CSV.\n")

        try:
            # store=False evita guardar todos os pacotes brutos na memoria.
            # Para IDS em Raspberry Pi/container, isso ajuda a reduzir consumo.
            sniff(
                iface=self.interface,
                filter=filtro,
                prn=self._processar_pacote,
                store=False,
                count=self.limite_pacotes,
            )
        except KeyboardInterrupt:
            print("\n--- Captura interrompida pelo usuario. ---")
        finally:
            # Mesmo com Ctrl+C, os registros ja analisados sao exportados.
            self.gerenciador_logs.exportar_para_csv()

    def _processar_pacote(self, pkt):
        """Converte um pacote bruto em registro de log quando ele for valido."""
        registro = self.analisador.analisar_pacote(pkt)
        if registro:
            self.gerenciador_logs.adicionar_registro(registro)
            print("Pacote detectado:")
            print(pkt.summary())

    def _montar_filtro(self):
        """Monta o filtro BPF usado pelo Scapy antes dos pacotes chegarem ao Python."""
        filtro = self.analisador.filtro_bpf
        if self.host:
            # Filtrar no BPF e mais eficiente do que capturar tudo e descartar depois.
            filtro = f"{filtro} and host {self.host}"
        return filtro
