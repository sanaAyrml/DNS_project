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
class User(Entity):
    def __init__(self, name, CA_pub_key):
        super().__init__(name,CA_pub_key)
        self.key_address = self.creat_key()
        print(self.key_address)



    # def symmetric_key_with_CA(self):
    #
    #     self.key = os.urandom(32)
    #     self.iv = os.urandom(16)
    #     cipher_key = self.encrypt_message_for_CA(self.key)
    #     cipher_iv = self.encrypt_message_for_CA(self.iv)
    #
    #     return cipher_key,cipher_iv
    #
    #     # cipher1 = Cipher(algorithms.AES(key), modes.CBC(iv))
    #     # cipher2 = Cipher(algorithms.AES(key), modes.CBC(iv))
    #     # encryptor = cipher1.encryptor()
    #     # ct = encryptor.update(self.signed_csr) + encryptor.finalize()
    #     # decryptor = cipher2.decryptor()
    #     # print(decryptor.update(ct) + decryptor.finalize())
    #     # print(type(f))
    #     # parameters = dh.generate_parameters(generator=2, key_size=2048)
    #     # print("herre2")
    #     # print(len(parameters.parameter_bytes(serialization.Encoding.PEM,serialization.ParameterFormat.PKCS3)))
    #     # server_private_key = parameters.generate_private_key()
    # def encrypt_message_for_CA(self,message):
    #     print("loook ",message)
    #     ciphertext = self.CA_pub_key.encrypt(message,
    #                                          padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
    #                                                       algorithm=hashes.SHA256(),
    #                                                       label=None))
    #     print(ciphertext)
    #     return ciphertext
    #
    # def send_csr_pack_to_CA(self):
    #     print("11")
    #     cipher_csr = self.encrupt_message_to_CA_symmetric(self.csr.public_bytes(serialization.Encoding.PEM))
    #     print("22")
    #     cipher_signed_csr = self.encrupt_message_to_CA_symmetric(self.signed_csr)
    #     return cipher_csr, cipher_signed_csr
    #
    # def encrupt_message_to_CA_symmetric(self,message):
    #     cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
    #     encryptor = cipher.encryptor()
    #     ct = encryptor.update(message)
    #     return ct
    #
