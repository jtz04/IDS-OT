"""Ponto de entrada do IDS.

Este arquivo apenas inicia e conecta as partes do sistema. A logica de captura,
analise de protocolo e persistencia fica nas classes de `core`, porque isso
deixa o projeto mais facil de evoluir: para adicionar outro protocolo, basta
criar outro analisador e registra-lo em `ANALISADORES`.
"""

import argparse

from core.logger import GerenciadorDeLogs
from core.parsers.modbus_parser import AnalisadorModbus
from core.parsers.mqtt_parser import AnalisadorMQTT
from core.sniffer import RedeSniffer


ANALISADORES = {
    # O dicionario funciona como um pequeno "registro" de protocolos.
    # Isso evita varios if/else espalhados pelo codigo e centraliza a escolha.
    "modbus": AnalisadorModbus,
    "mqtt": AnalisadorMQTT,
}


def criar_analisador(protocolo):
    """Cria a classe correta para o protocolo escolhido na linha de comando."""
    return ANALISADORES[protocolo]()


def caminho_padrao_saida(protocolo):
    """Gera um caminho de CSV padrao mantendo um arquivo por protocolo."""
    return f"/app/logs_{protocolo}.csv"


def parse_args():
    """Le os parametros de execucao sem misturar isso com a captura em si."""
    parser = argparse.ArgumentParser(description="Sensor IDS para trafego OT/IoT.")
    parser.add_argument(
        "--protocolo",
        choices=ANALISADORES.keys(),
        default="mqtt",
        help="Protocolo que sera monitorado.",
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
        help="Caminho do CSV de saida. Se omitido, usa /app/logs_<protocolo>.csv.",
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
    # - analisador: entende o protocolo;
    # - gerenciador_logs: guarda/exporta os registros;
    # - sniffer: captura pacotes e chama os outros dois.
    analisador = criar_analisador(args.protocolo)
    caminho_csv = args.saida or caminho_padrao_saida(args.protocolo)
    gerenciador_logs = GerenciadorDeLogs(caminho_csv)

    sniffer = RedeSniffer(
        analisador=analisador,
        gerenciador_logs=gerenciador_logs,
        interface=args.iface,
        host=args.host,
        limite_pacotes=args.limite,
    )
    sniffer.iniciar()


if __name__ == "__main__":
    main()
