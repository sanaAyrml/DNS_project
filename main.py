from user import User
from CA import CA
from merchant import Merchant
from bank import Bank
from blockChain import BlockChain

def ask_for_certificate(u1,u2,ca):
    csr, signed_csr, encrypted = u1.creat_csr(u2.uid)
    certificate, signed_certificate,encrypted = ca.get_csr(csr, signed_csr, encrypted)
    u1.get_certifcate(certificate, signed_certificate,encrypted)
    return

def deligation(u,bl,ca):
    ask_for_certificate(u,bl,ca)
    encrypted_param= u.set_deffie_helman_key_1()
    ask_for_certificate(bl,u,ca)
    encrypted_param = bl.set_deffie_helman_key_2(encrypted_param)
    encrypted_param = u.set_deffie_helman_key_3(encrypted_param)

    return

ca = CA("CA", None)

u = User(1,ca.pub_key)
ca.add_pubkey(1,u.get_pubkey())


m = Merchant(2,ca.pub_key)
ca.add_pubkey(2,m.get_pubkey())


bl = BlockChain(3,ca.pub_key)
ca.add_pubkey(3,bl.get_pubkey())

ba = Bank(4,ca.pub_key)
ca.add_pubkey(4,ba.get_pubkey())

deligation(u,bl,ca)


# cipher_key,cipher_iv = u1.symmetric_key_with_CA()
# ans = CA.set_symmetric_key(cipher_key,cipher_iv)
# if ans:
#     cipher_csr, cipher_signed_csr =u1.send_csr_pack_to_CA()
# CA.get_csr_from_user(cipher_csr, cipher_signed_csr)
# CA.verify_csr(signed_csr,csr)
# u1.encrypt_csr()