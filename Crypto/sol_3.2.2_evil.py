#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           �����17m�g�6����n2�{N����	��l�A\�oB�s�^�(X�,��^��C�C�\
]�湸�7����ֳK����E>��Z���r@>&�����c=w��e07;^�j|g㎿����T"""
from hashlib import sha256
if sha256(blob).hexdigest() == "b85012cdb6fb059cb61357cdeea54df85c7dca608e5cc978c2a421a6c24b04a7":
    print "I come in peace."
else:
    print "Prepare to be destroyed!"
