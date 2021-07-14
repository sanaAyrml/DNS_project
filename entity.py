import string

import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import uuid
import random
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Entity:
    def __init__(self, name: string,CA_pub_key):
        self.pub_key = None
        self.private_key = None
        self.uid = name
        self.CA_pub_key = CA_pub_key
        self.nuans = None


    def creat_key(self):
        one_day = datetime.timedelta(1, 0, 0)
        print(one_day)

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pub_key = self.private_key.public_key()


        path =  "./Keys/"+ str(self.uid)
        adress = path+"/ca.key"
        try:
            os.mkdir(path)
        except OSError as error:
            print(error)
        with open(adress, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"openstack-ansible")
            ))
        return adress

        # with open("/Keys/"+name+"/ca.key", "wb") as f:
        #     f.write(certificate.public_bytes(
        #         encoding=serialization.Encoding.PEM,
        # ))

    def get_pubkey(self):
        return self.pub_key

    def creat_csr(self, reciever_uid):

        self.csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Tehran"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Tehran"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"u1"),
            ])).sign(self.private_key,hashes.SHA256())
        self.signed_csr = self.private_key.sign(self.csr.public_bytes(serialization.Encoding.PEM),
                                           padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                                           hashes.SHA256())
        print("csr",self.csr)
        print("signed_csr",self.signed_csr)
        self.nuans = random.randint(0, 200)

        self.encrypted = self.encrypt_with_pub_key(bytes([self.uid,reciever_uid,self.nuans]),self.CA_pub_key)

        return self.csr,self.signed_csr,self.encrypted

    def encrypt_with_pub_key(self, message, pub_key):
        print("start encrypt")
        print(message)
        ciphertext = pub_key.encrypt(message,
                                             padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                          algorithm=hashes.SHA256(),
                                                          label=None))
        return ciphertext

    def decrypt_with_private_key(self, message):
        print("start decrypt")
        print(message)
        text = list(self.private_key.decrypt(message,
                                     padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(),
                                                  label=None)))
        print(text)
        return text

    def get_certifcate(self,certificate, signed_certificate,encrypted):

        list = self.decrypt_with_private_key(encrypted)
        self.verify_certificate(signed_certificate, certificate)
        if self.nuans + 1 == list[1]:
            print("True message")
        return

    def verify_certificate(self, signed_certificate, certificate):

        try:
            self.CA_pub_key.verify(signed_certificate,certificate.public_bytes(serialization.Encoding.PEM),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except cryptography.exceptions.InvalidSignature:
            print("invalid signature")
        return







