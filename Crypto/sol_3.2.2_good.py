#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           �����17m�g�6�Џ��n2�{N����	��l�A\�oB���^�(X�,��^�~C�C�\
]�湸�7����ֳK��g�E>��Z���r@>&�����c=w� f07;^�j|g㎿,���T"""
from hashlib import sha256
if sha256(blob).hexdigest() == "b85012cdb6fb059cb61357cdeea54df85c7dca608e5cc978c2a421a6c24b04a7":
    print "I come in peace."
else:
    print "Prepare to be destroyed!"
