# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from base64 import urlsafe_b64encode

import base64
import calendar
import json
import os
import time

import iso8601

import pytest

import six

from fernet2 import Fernet2, InvalidToken, MultiFernet
from PKFernet import PKFernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# from cryptography.hazmat.backends.interfaces import CipherBackend, HMACBackend
# from cryptography.hazmat.primitives.ciphers import algorithms, modes

# import cryptography_vectors

from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKeyWithSerialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PrivateFormat 
from cryptography.hazmat.primitives.serialization import PublicFormat


# Third-Party imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
# from cryptography.hazmat.primitives.interfaces import RSAPrivateKey, RSAPublicKey
def json_parametrize(keys, filename):
    vector_file = cryptography_vectors.open_vector_file(
        os.path.join('fernet', filename), "r"
    )
    with vector_file:
        data = json.load(vector_file)
        return pytest.mark.parametrize(keys, [
            tuple([entry[k] for k in keys])
            for entry in data
        ])


def test_default_backend():
    f = Fernet2(Fernet2.generate_key())
    assert f._backend is default_backend()


@pytest.mark.parametrize("backend", [default_backend()])
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES("\x00" * 32), modes.CBC("\x00" * 16)
    ),
    skip_message="Does not support AES CBC",
)
class TestFernet(object):
    """This is basically the tests given in test_fernet.py. This tests
    the bacward compatibility of the new Fernet2. 
    """

def generate_keypair(alias):
    # Why is there several keys for one version in the spec?
    # receiver1 = "ecc.secp2241.1.enc.priv"
    # TODO: does this have to be genertated by a specific algorithim 
    #  like: ec.generate_private_key( ec.SECP384R1(), default_backend()) ?
    # priv_key1 = urlsafe_b64encode("This is my super secure key!")
    # c = " {0} :   -----BEGIN EC PRIVATE KEY-----\n {1} \n-----END EC PRIVATE KEY-----\n".format(receiver1, priv_key1)
    # 

    # if
    curve = eval("ec.SECP192R1()") 
    priv_key = ec.generate_private_key(curve, default_backend())
    # print(priv_key)
    # print(isinstance(priv_key, ec.EllipticCurvePrivateKey))
    # serializate the private key
    # eccPrivateKey = EllipticCurvePrivateKeyWithSerialization()

    # print( eccPrivateKey.private_bytes(priv_key, Encoding.PEM, PrivateFormat.PKCS8) )
    private_key = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    print(private_key)
    # generate public key with crypto lib
    # g^x , crypto lib.. public key... 
    pub_key = priv_key.public_key()

    public_key = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            # encryption_algorithm=serialization.NoEncryption()
        )
    print(public_key)

    # return public and private key pair
    return private_key, public_key



class TestPKFernet(object):
    """Test the new Fernet2 with this class. Make sure it tests all the
    functionalities offered by *PKFernet*.
    """
    # with open('public_keys','rb') as json_file:
    #     json_data = json.load(json_file)

    # receiver_key_dict = {}
    # # key  = load_pem_public_key(pkeydata, backend=default_backend())
    # for r in json_data:
    # #     receiver_key_dict.add(r)
    #     receiver_key_dict[r] =json_data[r].strip("-----BEGIN PUBLIC KEY-----").strip("\n-----END PUBLIC KEY-----")
    #     # a = json_data[r]
        # print(r)
        # print(receiver_key_dict[r])

    # private_key = ec.generate_private_key(ec.SECP224R1(), default_backend())
    # print(private_key)
    
    # private_keyring = generate_private_key_ring()
    # print(private_keyring)
    # public_keyring = urlsafe_b64encode("This is my super secure key!")
    # # print(len("This is my super secure key!"), key_priv, len(key_priv))
    # adata = "Sample associated data" 

    # get priv and pub keyrings
    
    # private_keyring, public_keyring = 
    generate_keypair("alias 1")

    # print(private_keyring, public_keyring)
    public_keyrings = {}
    '''
    # multiple recievers public keyrings
    # others public key
    # inputs need to be keyring format.
    pf = PKFernet(private_keyring, public_keyrings)

    # # ecc.secp224r1.enc.priv
    receiver_private_key, receiver_public_key = generate_keypair("alias 2")
    receiver_private_key, receiver_public_key2 = generate_keypair("alias 3")

    pf.import_pub_key(receiver_name, receiver_public_keyring)

    # receiver_ame = random name
    # # where does this go? what dpes it do?
    # my_pub_keys_json_blob = pf.export_pub_keys(key_alias_list=[])


    c = pf.encrypt(msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, adata='', sign_also=True)
    # m = pf.decrypt(ctx, sender_name, verfiy_also=True)
'''

