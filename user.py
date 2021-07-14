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
import threading
import socket
import pickle
import struct
import base64

class User(Entity):
    def __init__(self, name, CA_pub_key):
        super().__init__(name, CA_pub_key)
        self.key_address = self.creat_key()
        self.host = "127.0.0.1"
        self.port = 2004
        self.CA_host = "127.0.0.1"
        self.CA_port = 3016
        # self.receiver = Receiver(self.host, self.port)
        # self.receiver.start()
        print(self.key_address)

    def start_communication(self, user_id):
        csr, signed_csr, encrypted = self.creat_csr(user_id)

        # print("sadiasfasofnasoifjaisjfoisajf", type(signed_csr))
        encoded = base64.b64encode(signed_csr)
        encoded1 = base64.b64encode(encrypted)
        message = (csr.__str__(), encoded.decode("ascii"), encoded1.decode("ascii"))
        # print(message)
        # print("---------------------------------------------------------------")
        # print(message)
        sender = Sender(self.CA_host, self.CA_port, message)
        sender.start()

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

class Receiver(threading.Thread):
    def __init__(self, my_host, my_port):
        threading.Thread.__init__(self, name="receiver")
        self.host = my_host
        self.port = my_port

    def listen(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(10)
        while True:
            connection, client_address = sock.accept()
            try:
                full_message = ""
                while True:
                    data = connection.recv(16)
                    full_message = full_message + data.decode("utf-8")
                    if not data:
                        print("{}: {}".format(client_address, full_message.strip()))
                        break
            finally:
                # connection.shutdown(2)
                # connection.close()
                pass

    def run(self):
        self.listen()


class Sender(threading.Thread):

    def __init__(self, my_friends_host, my_friends_port, message):
        threading.Thread.__init__(self, name="sender")
        self.host = my_friends_host
        self.port = my_friends_port
        self.message = json.dumps(message)

    def run(self):
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))
            s.send(self.message.encode("utf-8"))
            s.shutdown(2)
            s.close()


