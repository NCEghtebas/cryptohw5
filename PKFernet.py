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

	def __init__(self, private_keyring, public_keyrings, backend=None):
		# empty dictionary for receivers and their public key rings

		self.recerver_dict = {}

		if backend is None:
			backend = default_backend()

		# private key
		self.private_keyring =  private_keyring 
		# make it of the 
		# { rahul: { "": asdf, "": asdfsf } ,  asheesh}
		self.public_keyrings = public.keyrings 
		self._backend = backend

	@classmethod
	def generate_key(cls):
		return base64.urlsafe_b64encode(os.urandom(32))

	def encrypt(self, msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, adata = '', sign_also=True):
		# pass
		# signing?

		# fernet..

		# return  adata| <encryption header> | <shared secret> | ctx 
		pass 
	def decrypt(self, ctx, sender_name, verfiy_also=True):
		pass
	# my_pub_keys_json_blob = pf.export_pub_keys(key_alias_list=[])
	def export_pub_keys(self, key_alias_list=[]):

		pass
	# pf.import_pub_keys(receiver_name, receiver_public_keyring)
	# takes recivers name and public keyring
	def import_pub_key(self, receiver_name, receiver_public_keyring):
		if receiver_name in self.recerver_dict.keys():
			for key in receiver_public_keyring:
				self.recerver_dict[receiver_name].add(key)
		else:
			self.recerver_dict[receiver_name] = {}
			for key in receiver_public_keyring:
				self.recerver_dict[receiver_name].add(key)

		pass
