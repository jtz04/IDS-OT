"""Transforma logs capturados em features para modelos de ML.

Este arquivo ainda esta como ponto de extensao. A ideia e manter a preparacao
dos dados separada dos parsers: parsers entendem protocolos, enquanto este
modulo devera transformar colunas como Tipo, QoS, Funcao e Tamanho_Payload em
valores numericos para o modelo de anomalia.
"""
