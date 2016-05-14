__author__ = 'yiqingluo'
# import os
# import rsa
import json
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.backends import default_backend
with open('public_keys','rb') as json_file:
    json_data = json.load(json_file)

# key  = load_pem_public_key(pkeydata, backend=default_backend())
for r in json_data:
    print r
    a = json_data[r]
    print a.strip("-----BEGIN PUBLIC KEY-----").strip("\n-----END PUBLIC KEY-----")
# print isinstance(key, rsa.RSAPublicKey)
# # pubkey = rsa.PublicKey.load_pkcs1(pkeydata)
#
# random_text = os.urandom(8)
#
# #Generate signature
# signature = rsa.sign(random_text, privkey, 'MD5')
# print signature
#
# #Verify token
# try:
#     rsa.verify(random_text, signature, pubkey)
# except:
#     print "Verification failed"
