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
