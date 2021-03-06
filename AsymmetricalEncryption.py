import base64
from abc import ABC
from Crypto import *
from Crypto import Random
from Crypto.PublicKey import *
from Crypto.Random import random as rd
from Crypto.Util.number import GCD


class AsymmetricEncryption(ABC):

    def encrypt(self, plain_text):
        pass

    def decrypt(self, cipher_text):
        pass

    def sign(self, message):
        pass

    def verify(self, message, signature):
        pass

    def is_private(self):
        pass


class ElGamalEncryption(AsymmetricEncryption):

    def __init__(self):
        self.__key = None

    def construct_key(self, tup: tuple):
        self.__key = ElGamal.construct(tup)

    def generate_key(self, size: int = 1024, rand_func = Random.new().read):
        self.__key = ElGamal.generate(size, rand_func)

    def __generate_k(self):
        while 1:
            k = rd.StrongRandom().randint(1, self.__key.p - 1)
            if GCD(k, self.__key.p - 1) == 1:
                return k

    def export_private_key(self):
        return "\n".join(["{} = {}".format(comp, getattr(self.__key, comp)) for comp in self.__key.keydata])

    def export_public_key(self):
        return "\n".join(["{} = {}".format(comp, getattr(self.__key.publickey(), comp)) for comp in ['p', 'g', 'y']])

    def encrypt(self, plain_text):
        k = self.__generate_k()
        cipher_text = self.__key.encrypt(plain_text.encode('utf-8'), k)
        return tuple(base64.b64encode(c).decode('utf-8') for c in cipher_text)

    def decrypt(self, cipher_text):
        cipher_text = tuple(base64.b64decode(c.encode('utf-8')) for c in cipher_text)
        plain_text = self.__key.decrypt(cipher_text)
        return plain_text.decode('utf-8')

    def sign(self, message):
        h = Hash.SHA.new(message.encode('utf-8')).digest()
        while 1:
            k = rd.StrongRandom().randint(1, self.__key.p - 1)
            if GCD(k, self.__key.p - 1) == 1:
                break
        sig = self.__key.sign(h, k)
        return sig

    def verify(self, message, signature):
        h = Hash.SHA.new(message.encode('utf-8')).digest()
        return bool(self.__key.verify(h, signature))

    def is_private(self):
        return self.__key.has_private()


def import_rsa_key(file_path, passphrase=None):
    try:
        f = open(file_path, 'r')
        rsa_byte = f.read()
        rsa_key = RSA.importKey(rsa_byte, passphrase=passphrase)
        f.close()
        return rsa_key
    except Exception:
        raise Exception(
            'The specified file [' + file_path + '] does not exist or does not contain a valid RSA Key in bytes format')


class RSAEncryption:
    def __init__(self):
        self.__passphrase: str = ''
        self.__key: RSA = None

    def import_key(self, file_path: str, passphrase: str = None):
        self.__key = import_rsa_key(file_path, passphrase=passphrase)
        self.__passphrase = passphrase

    def generate_key(self, size=1024, passphrase=None):
        self.__key = RSA.generate(int(size))
        self.__passphrase = passphrase

    def export_private_key(self, output_file=None, passphrase=None):
        if output_file is not None:
            f = open(output_file, 'w')
            f.write(self.__key.exportKey(format='PEM', passphrase=passphrase).decode())
            f.close()

    def export_public_key(self, output_file=None, passphrase=None):
        if output_file is not None:
            f = open(output_file, 'w')
            f.write(self.__key.publickey().exportKey(format='PEM', passphrase=passphrase).decode())
            f.close()

    def encrypt(self, plain_text):
        plain_text = plain_text.encode('utf-8')
        rsa_key = self.__key
        return base64.b64encode(rsa_key.encrypt(plain_text, 32)[0]).decode('utf-8')

    def decrypt(self, cipher_text):
        cipher_text = base64.b64decode(cipher_text.encode('utf-8'))
        plain_text = self.__key.decrypt(cipher_text)
        return plain_text.decode('utf-8')

    def sign(self, message):
        h = Hash.SHA.new(message.encode('utf-8')).digest()
        return self.__key.sign(h, 32)[0]

    def verify(self, message, signature):
        h = Hash.SHA.new(message.encode('utf-8')).digest()
        return self.__key.verify(h, (signature, 32))

    def is_private(self):
        return self.__key.has_private()
