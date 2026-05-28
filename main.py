"""Ponto de entrada do IDS.

Este arquivo apenas inicia e conecta as partes do sistema. A captura principal
do projeto monitora Modbus e MQTT ao mesmo tempo, porque o objetivo do sensor e
observar o trafego OT/IoT completo e exportar tudo em um unico CSV.
"""

import argparse

from core.logger import GerenciadorDeLogs
from core.parsers.modbus_parser import AnalisadorModbus
from core.parsers.mqtt_parser import AnalisadorMQTT
from core.sniffer import RedeSniffer


def criar_analisadores():
    """Cria todos os analisadores que devem rodar simultaneamente."""
    return [
        AnalisadorModbus(),
        AnalisadorMQTT(),
    ]


def caminho_padrao_saida():
    """Gera o caminho do CSV unificado da captura IDS."""
    return "/app/logs_ids.csv"


def parse_args():
    """Le os parametros de execucao sem misturar isso com a captura em si."""
    parser = argparse.ArgumentParser(description="Sensor IDS para trafego OT/IoT.")
    parser.add_argument(
        "--protocolo",
        default=None,
        help=(
            "Parametro mantido apenas por compatibilidade. "
            "A captura sempre monitora Modbus e MQTT ao mesmo tempo."
        ),
    )
    parser.add_argument(
        "--iface",
        default="eth0",
        help="Interface de rede usada pelo Scapy.",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Host opcional para restringir o filtro BPF.",
    )
    parser.add_argument(
        "--saida",
        default=None,
        help="Caminho do CSV de saida. Se omitido, usa /app/logs_ids.csv.",
    )
    parser.add_argument(
        "--limite",
        type=int,
        default=0,
        help="Quantidade maxima de pacotes para capturar. Zero captura indefinidamente.",
    )
    return parser.parse_args()


def main():
    """Monta os objetos principais e entrega o controle para o sniffer."""
    args = parse_args()

    # Cada objeto tem uma responsabilidade unica:
    # - analisadores: entendem Modbus e MQTT;
    # - gerenciador_logs: guarda/exporta os registros;
    # - sniffer: captura pacotes uma vez e chama os parsers dos dois protocolos.
    analisadores = criar_analisadores()
    caminho_csv = args.saida or caminho_padrao_saida()
    gerenciador_logs = GerenciadorDeLogs(caminho_csv)

    sniffer = RedeSniffer(
        analisadores=analisadores,
        gerenciador_logs=gerenciador_logs,
        interface=args.iface,
        host=args.host,
        limite_pacotes=args.limite,
    )
    sniffer.iniciar()


if __name__ == "__main__":
    main()
