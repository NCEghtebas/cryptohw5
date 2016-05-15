from __future__ import absolute_import, division, print_function

import base64
import binascii
import os
import struct
import time

import six

from fernet2 import Fernet2 
from base64 import urlsafe_b64encode


from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf import hkdf
from fernet import Fernet
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat 
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.asymmetric import ec as ecc
# Third-Party imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa


class InvalidToken(Exception):
    pass

def generate_keypair(alias):
    # Why is there several keys for one version in the spec?
    # receiver1 = "ecc.secp2241.1.enc.priv"
    # TODO: does this have to be genertated by a specific algorithim 
    #  like: ec.generate_private_key( ec.SECP384R1(), default_backend()) ?
    # priv_key1 = urlsafe_b64encode("This is my super secure key!")
    # c = " {0} :   -----BEGIN EC PRIVATE KEY-----\n {1} \n-----END EC PRIVATE KEY-----\n".format(receiver1, priv_key1)
    # 

    # if
    algo = alias.split(".")[0]
    key_para = alias.split(".")[1].upper()
    version = alias.split(".")[2]
    usage = alias.split(".")[3]
    key_type = alias.split(".")[4]

    # "ec.SECP192R1()" 
    if algo == "ecc":
        curve = eval(algo+"."+key_para+ "()") 
        priv_key = ecc.generate_private_key(curve, default_backend())
		pub_key = priv_key.public_key()
    elif algo == "dsa":
        priv_key = dsa.generate_private_key(
            key_size= 2048,
            backend=default_backend())
		pub_key = priv_key.public_key()
    else:
        print("not valid")

	# pub_key = priv_key.public_key()

    return priv_key, pub_key

class PKFernet(object):

	def __init__(self, private_keyring, public_keyrings, backend=None):
		# empty dictionary for receivers and their public key rings


		if backend is None:
			backend = default_backend()
		# generate 

		# private key
		self.private_keyring =  private_keyring 
		# make it of the 
		# { rahul: { "": asdf, "": asdfsf } ,  asheesh}
		self.public_keyrings = public_keyrings 
		self._backend = backend

	@classmethod
	def generate_key(cls):
		return base64.urlsafe_b64encode(os.urandom(32))

	def encrypt(self, msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header , adata = '', sign_also=True):

		e_private_key, e_public_key = generate_keypair(receiver_enc_pub_key_alias)

		rec_pub_enc_key = self.public_keyrings[receiver_name][receiver_enc_pub_key_alias]
	

		shared_key = e_private_key.exchange(ecc.ECDH(), rec_pub_enc_key) 


  		algo = sender_sign_header.split(".")[0]
  		key_para = sender_sign_header.split(".")[1]

  		if algo == "ecdsa_with_sha256":
  			
  			
			signer = e_private_key.signer(ecc.ECDSA(hashes.SHA256()))
		else:
			print("signature not supported")
		data = urlsafe_b64encode(msg)
		signer.update(data)
		signature = signer.finalize()

		m = msg + "|" + sender_sign_header + "|" + signature
		m_utf8 = urlsafe_b64encode(m)

		# print(m)
		# signature message... 
		# need correct encoded.. urlbase64. 
		# signing.. choose one algo that we like
		fnt = Fernet2(urlsafe_b64encode(shared_key))
		ctxt = fnt.encrypt(m_utf, associated_data=adata)
		# todo... for e_public key
		 # public_key = pub_key.public_bytes(
   #          encoding=serialization.Encoding.PEM,
   #          format=serialization.PublicFormat.SubjectPublicKeyInfo,
   #          # encryption_algorithm=serialization.NoEncryption()
   #      )


		# shared secret = Rpk
		return  adata + "|" + receiver_enc_pub_key_alias + "|" +  urlsafe_b64encode(e_public_key) + "|" + ctxt 

	def decrypt(self, ctx, sender_name, verfiy_also=True):
		# ptxt = fnt.decrypt(ctxt, associated_data=adata)
		
		adata = ctx.split("|")[0]
		encryption_algorithm = ctx.split("|")[1]
		e_public_key = ctx.split("|")[2]
		ctx = ctx.split("|")[3]


		# generate shared

		shared_key = my_keyrig.exchange(ec.ECDH(), e_pub_enc_key) #g^xy

		# decrypt message

		fnt = Fernet2( shared_key)
		ptxt = fnt.decrypt(ctxt, associated_data=adata)

		# only m is data
		# m = 
		# sender_sign_header = 
		# signature =

		# based on header.. we can do hashes.___

		# use public key of reciever
		verifier = public_key.verifier(signature, hashes.SHA256())
		verifier.update(data)
		verifier.verify()

		return plaintxt


	# my_pub_keys_json_blob = pf.export_pub_keys(key_alias_list=[])
	def export_pub_keys(self, key_alias_list=[]):

		pass
	# pf.import_pub_keys(receiver_name, receiver_public_keyring)
	# takes recivers name and public keyring
	def import_pub_key(self, receiver_name, receiver_public_keyrings):
		# print(self.public_keyrings)
		# print(receiver_public_keyrings)
		if self.public_keyrings.has_key(receiver_name):
			keyring_dict = receiver_public_keyrings
			for alias in keyring_dict.keys():
				self.public_keyrings[receiver_name][alias] = keyring_dict[alias]
		else:
			self.public_keyrings[receiver_name] = receiver_public_keyrings


		# print(receiver_name)
		# print(self.public_keyrings["tom"])
		# print(self.public_keyrings["tom"]["alias 2"])
		# print(self.public_keyrings["tom"])
		# if receiver_name in self.receiver_dict.keys():

		# 	for keyring in list(receiver_public_keyrings.keys()):
		# 		print receiver_public_keyrings.get(keyring)				
		# 		# pass
		# 		# self.receiver_dict[receiver_name].append(keyring)
		# else:
		# 	self.receiver_dict[receiver_name] = {}
		# 	for keyring in receiver_public_keyrings:
		# 		pass
				# self.receiver_dict[receiver_name].append(keyring)

