"""Captura bruta de pacotes de rede.

A classe `RedeSniffer` nao conhece detalhes internos de Modbus ou MQTT. Ela
recebe uma lista de analisadores e envia cada pacote capturado para todos eles.
Essa escolha aplica composicao: o mesmo sniffer captura uma unica vez e varios
parsers podem tentar interpretar o pacote ao mesmo tempo.
"""

from scapy.all import sniff


class RedeSniffer:
    """Coordena a captura Scapy e envia cada pacote aos analisadores configurados."""

    def __init__(self, analisadores, gerenciador_logs, interface="eth0", host=None, limite_pacotes=0):
        # Receber as dependencias no construtor deixa a classe reutilizavel.
        # Ela nao precisa criar parsers nem logger por conta propria.
        self.analisadores = analisadores
        self.gerenciador_logs = gerenciador_logs
        self.interface = interface
        self.host = host
        self.limite_pacotes = limite_pacotes

    def iniciar(self):
        """Inicia a captura e garante a exportacao dos logs ao final."""
        filtro = self._montar_filtro()

        print("---- Iniciando sensor IDS na rede virtual ----")
        print(f"Protocolos monitorados: {self._nomes_dos_protocolos()}")
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
        # O mesmo pacote e entregue para todos os analisadores. Apenas o parser
        # do protocolo correspondente retorna um registro; os demais retornam None.
        for analisador in self.analisadores:
            registro = analisador.analisar_pacote(pkt)
            if registro:
                self.gerenciador_logs.adicionar_registro(registro)
                print("Pacote detectado:")
                print(pkt.summary())
                break

    def _montar_filtro(self):
        """Monta o filtro BPF usado pelo Scapy antes dos pacotes chegarem ao Python."""
        # O filtro usa OR para capturar Modbus e MQTT na mesma chamada sniff().
        filtros_protocolos = [analisador.filtro_bpf for analisador in self.analisadores]
        filtro = " or ".join(f"({filtro})" for filtro in filtros_protocolos)
        if self.host:
            # Filtrar no BPF e mais eficiente do que capturar tudo e descartar depois.
            filtro = f"({filtro}) and host {self.host}"
        return filtro

    def _nomes_dos_protocolos(self):
        """Retorna uma string amigavel com os protocolos ativos."""
        return ", ".join(analisador.nome for analisador in self.analisadores)
