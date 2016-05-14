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
from PKFernet import PKFernet, generate_keypair
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
    
    # ours
    sender_private_key, sender_public_key = generate_keypair("ecc.secp224r1.1.enc.pub")

    # print(sender_private_key)


    # print(private_keyring, public_keyring)
    public_keyrings = {}
    # {"tom" : "{'alias 2': "'-----BEGIN PUBLIC KEY-----\nMEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAERUrw9VGhAXM/uCLGi1U0ntfCB+Nh\nMfaByyOXdsq/1zTvdp61uNTEb65nZHbfJ1Gq\n-----END PUBLIC KEY-----\n'} "}
    
    # multiple recievers public keyrings
    # others public key
    # inputs need to be keyring format.
    pf = PKFernet(sender_private_key, public_keyrings)

    # # ecc.secp224r1.enc.priv
    # theirs
    receiver_private_key, receiver_public_key = generate_keypair("ecc.secp224r1.1.enc.pub")
    receiver_private_key, receiver_public_key2 = generate_keypair("alias 3")
    # print(receiver_public_key)
    # print(type(receiver_public_key))

    receiver_pub_keyring1_dict1 = {"ecc.secp224r1.1.enc.pub":receiver_public_key}
    receiver_pub_keyring1_dict2 = {"alias3":receiver_public_key2}

    pf.import_pub_key("tom", receiver_pub_keyring1_dict1)
    
    pf.import_pub_key("rah", receiver_pub_keyring1_dict2)
    
    

    # receiver_ame = random name
    # # where does this go? what dpes it do?
    # my_pub_keys_json_blob = pf.export_pub_keys(key_alias_list=[])

    msg = "A+++++ cyrpto for Chloe and Yiqing"
    receiver_name = "tom"
    receiver_enc_pub_key_alias = "ecc.secp224r1.1.enc.pub"
    sender_sign_header = "ecdh_with_DSA. "
    c = pf.encrypt(msg, receiver_name, receiver_enc_pub_key_alias, sender_sign_header, adata='', sign_also=True)

    # m = pf.decrypt(ctx, sender_name, verfiy_also=True)


