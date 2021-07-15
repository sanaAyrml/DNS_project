import pickle
import string
from binascii import unhexlify

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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Entity:
    def __init__(self, name: string,CA_pub_key):
        self.pub_key = None
        self.private_key = None
        self.uid = name
        self.CA_pub_key = CA_pub_key
        self.nuans = None
        self.reciever_pub_key = None
        self.reciever_uid = None
        self.reciever_certificate = None
        self.dh_p = None
        self.dh_g = None
        self.recived_nuans = None
        self.dh_private_key = None
        self.dh_reciver_public_key = None
        self.dh_shared_key = None
        self.dh_derived_key = None


    def creat_key(self):
        one_day = datetime.timedelta(1, 0, 0)

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pub_key = self.private_key.public_key()

        try:
            os.mkdir("./Keys")
        except OSError as error:
            pass

        path =  "./Keys/"+ str(self.uid)
        adress = path+"/"+str(self.uid)+".key"
        try:
            os.mkdir(path)
        except OSError as error:
            pass
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
        self.reciever_uid = reciever_uid

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

        self.nuans = random.randint(0, 200)

        self.encrypted = self.encrypt_with_pub_key(bytes([self.uid,reciever_uid,self.nuans]),self.CA_pub_key)

        return self.csr,self.signed_csr,self.encrypted

    def encrypt_with_pub_key(self, message, pub_key):

        encrypted_param = []
        i  = 0
        while i < len(message):
            en = pub_key.encrypt(message[i:i+100],
                                         padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                      algorithm=hashes.SHA256(),
                                                      label=None))
            encrypted_param.append(en)
            i += 100


        return encrypted_param

    def decrypt_with_private_key(self, message):
        de = b''
        for m in message:
            de += self.private_key.decrypt(m,
                                           padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None))
        return de

    def get_certifcate(self,certificate, signed_certificate,encrypted):
        self.reciever_certificate = certificate
        l = list(self.decrypt_with_private_key(encrypted))
        self.verify_certificate(signed_certificate, certificate)
        if self.nuans + 1 == l[1]:
            print("True message")
        self.reciever_pub_key = certificate.public_key()
        return

    def verify_certificate(self, signed_certificate, certificate):

        try:
            self.CA_pub_key.verify(signed_certificate,certificate.public_bytes(serialization.Encoding.PEM),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except cryptography.exceptions.InvalidSignature:
            print("invalid signature")
        return

    def set_deffie_helman_key_1(self):
        parameters = dh.generate_parameters(generator=2, key_size=512)
        self.dh_private_key = parameters.generate_private_key()

        self.dh_p = parameters.parameter_numbers().p
        self.dh_g = parameters.parameter_numbers().g
        self.nuans = random.randint(0, 10000)

        list_param = [self.uid,self.reciever_uid,self.dh_p,self.dh_g,self.dh_private_key.public_key().public_numbers().y,self.nuans]
        o=pickle.dumps(list_param)

        encrypted_param = self.encrypt_with_pub_key(o,self.reciever_pub_key)


        return encrypted_param


    def set_deffie_helman_key_2(self,encrypted_param):

        en = self.decrypt_with_private_key(encrypted_param)
        kj = pickle.loads(en)
        self.dh_p = kj[2]
        self.dh_g = kj[3]
        self.dh_y = kj[4]
        self.recived_nuans = kj[5]

        pn = dh.DHParameterNumbers(self.dh_p, self.dh_g)
        parameters = pn.parameters()
        peer_public_numbers = dh.DHPublicNumbers(self.dh_y, pn)
        self.dh_reciver_public_key = peer_public_numbers.public_key()
        self.dh_private_key = parameters.generate_private_key()
        self.dh_shared_key = self.dh_private_key.exchange(self.dh_reciver_public_key)
        self.dh_derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(self.dh_shared_key)

        self.nuans = random.randint(0, 10000)

        list_param = [self.uid,self.reciever_uid, self.dh_private_key.public_key().public_numbers().y,self.nuans,self.recived_nuans+1]
        o=pickle.dumps(list_param)

        encrypted_param = self.encrypt_with_pub_key(o,self.reciever_pub_key)

        return encrypted_param

    def set_deffie_helman_key_3(self,encrypted_param):

        en = self.decrypt_with_private_key(encrypted_param)
        kj = pickle.loads(en)
        self.dh_y = kj[2]
        self.recived_nuans = kj[3]
        if self.nuans +1 == kj[4]:
            print("true message")
        else:
            print("wrong message")

        pn = dh.DHParameterNumbers(self.dh_p, self.dh_g)
        peer_public_numbers = dh.DHPublicNumbers(self.dh_y, pn)
        self.dh_reciver_public_key = peer_public_numbers.public_key()
        self.dh_shared_key = self.dh_private_key.exchange(self.dh_reciver_public_key)
        self.dh_derived_key = HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'handshake data',).derive(self.dh_shared_key)
        return

    def encrypt_with_session_key(self,message):
        cipher = Cipher(algorithms.AES(self.dh_derived_key), modes.CBC(b"a" * 16))
        encryptor = cipher.encryptor()
        ct = encryptor.update(message) + encryptor.finalize()
        return ct

    def decrypt_with_session_key(self,message):
        cipher = Cipher(algorithms.AES(self.dh_derived_key), modes.CBC(b"a" * 16))
        decryptor = cipher.decryptor()
        return decryptor.update(message) + decryptor.finalize()


