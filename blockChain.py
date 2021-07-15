import pickle

import cryptography
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from entity import Entity
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json
import string
class BlockChain(Entity):
    def __init__(self, name, CA_pub_key):
        super().__init__(name,CA_pub_key)
        self.key_address = self.creat_key()
        print(self.key_address)
        self.dict_policies = {}

    def verify_policy(self,policy,signed_policy):
        try:
            self.reciever_pub_key.verify(signed_policy,pickle.dumps(policy),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except cryptography.exceptions.InvalidSignature:
            print("invalid signature")
        return

    def recieve_deligation(self,encrypted_param):
        en = self.decrypt_with_session_key(encrypted_param)
        kj = pickle.loads(en)
        self.verify_policy(kj[3],kj[4])
        self.dict_policies[kj[0]] = kj[3]
        list_param = [kj[2]+1]
        o=pickle.dumps(list_param)
        encrypted_param = self.encrypt_with_session_key(o)
        return encrypted_param
