import cryptography
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
import datetime
import uuid
from entity import Entity
from cryptography.hazmat.primitives.asymmetric import padding
import string
class CA(Entity):
    def __init__(self, name: string, CA_pub_key):
        super().__init__(name, CA_pub_key)
        self.pubkey_dict = {}
        self.key_address = self.creat_key()

    def add_pubkey(self,name,pubkey):
        self.pubkey_dict[name] = pubkey
        print(self.pubkey_dict)

    def get_csr(self,csr, signed_csr, encrypted):
        l = list(self.decrypt_with_private_key(encrypted))
        self.verify_csr(signed_csr,csr,l[0])
        certificate, signed_certificate = self.creat_crt(l[1])
        encrypted = self.encrypt_with_pub_key([l[1],l[2]+1],self.pubkey_dict[l[0]])
        return certificate, signed_certificate,encrypted


    def verify_csr(self, signed_csr, csr,uid):

        try:
            self.pubkey_dict[uid].verify(signed_csr,csr.public_bytes(serialization.Encoding.PEM),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except cryptography.exceptions.InvalidSignature:
            print("invalid signature")

    def creat_crt(self,certificate_uid):
        one_day = datetime.timedelta(1, 0, 0)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'openstack-ansible Test CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'openstack-ansible'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Default CA Deployment'),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'openstack-ansible Test CA'),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime(2021, 8, 2))
        builder = builder.serial_number(int(uuid.uuid4()))
        builder = builder.public_key(self.pubkey_dict[certificate_uid])
        certificate = builder.sign(
            private_key=self.private_key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        signed_certificate = self.private_key.sign(certificate.public_bytes(serialization.Encoding.PEM),
                                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
                                                hashes.SHA256())
        return certificate,signed_certificate


    # def set_symmetric_key(self,cipher_key,cipher_iv):
    #     self.key = self.decrypt_message(cipher_key)
    #     self.iv = self.decrypt_message(cipher_iv)
    #     return True
    #
    # def decrypt_message(self,message):
    #
    #     text = self.private_key.decrypt(message,
    #                                          padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
    #                                                       algorithm=hashes.SHA256(),
    #                                                       label=None))
    #
    #     return text
    #
    # def get_csr_from_user(self,cipher_csr, cipher_signed_csr):
    #     csr = self.decrypte_symmetric(cipher_csr)
    #     signed_csr = self.decrypte_symmetric(cipher_signed_csr)
    #     self.verify_csr(signed_csr,csr)
    #     return
    #
    # def decrypte_symmetric(self,message):
    #     cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
    #     decryptor = cipher.decryptor()
    #     t = decryptor.update(message) + decryptor.finalize()
    #     return t
    #
    #
