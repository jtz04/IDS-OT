"""Carregamento e uso do modelo de deteccao de anomalias.

Este arquivo fica separado do sniffer para que a captura continue simples e
testavel. Quando houver um modelo treinado em `ai/modelos_treianados`, este
modulo deve carregar o artefato e receber as features geradas pelo
`extrator_features.py`.
"""
