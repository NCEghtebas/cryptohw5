from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
import struct
import time

import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf import hkdf
from fernet import Fernet

class InvalidToken(Exception):
    pass

class PKFernet(object): 
    def __init__(self, private_keyring, public_keyring, backend=None): 
    def encrypt(self, msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, adata=‘’, sign_also=True):  
    def decrypt(self, ctx, sender_name, verfiy_also=True):  
    # >>> my_pub_keys_json_blob = pf.export_pub_keys(key_alias_list=[]) 
    def export_pub_keys(self, key_alias_list=[]):  
    # >>> pf.import_pub_keys(receiver_name, receiver_public_keyring)  
    def import_pub_keys(self, receiver_name, receiver_public_keyring):  
