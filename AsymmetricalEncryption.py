import base64
from abc import ABC

from crypto import *
from crypto import Random
from crypto.PublicKey import *
from crypto.Random import random as rd
from crypto.Util.number import GCD


class Asym_Encryption(ABC):

    def encrypt(self, plain_text):
        pass

    def decrypt(self, cipher_text):
        pass

    def sign(self, message):
        pass

    def verify(self, message, signature):
        pass


class ElGamalEncryption(Asym_Encryption):

    def __init__(self, tup: tuple):
        self.__key = ElGamal.construct(tup)

    def __init__(self, size: int = 1024, rand_func=Random.new().read):
        self.__key = ElGamal.generate(size, rand_func)

    def __generate_k(self):
        while 1:
            k = rd.StrongRandom().randint(1, self.__key.p - 1)
            if GCD(k, self.__key.p - 1) == 1:
                return k

    def encrypt(self, plain_text):
        k = self.__generate_k()
        cipher_text = self.__key.encrypt(plain_text.encode('utf-8'), k)
        return cipher_text

    def decrypt(self, cipher_text):
        cipher_text = base64.b64decode(cipher_text.encode('utf-8'))
        plain_text = self.__key.decrypt(cipher_text)
        return plain_text

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


class RSAEncryption():
    def __init__(self, tup: tuple):
        self.__key = RSA.construct(tup)

    def __init__(self, file_path: str, passphrase: str=None):
        self.__key = self.__import_rsa_key(file_path, passphrase=passphrase)
        self.__passphrase = passphrase

    def __init__(self, size=1024, output_file=None, passphrase=None):
        self.__key = self.__generate_rsa_key(size, output_file, passphrase)
        self.__passphrase

    def encrypt(self, plain_text):
        plain_text = plain_text.encode('utf-8')
        rsa_key = self.__key
        return base64.b64encode(rsa_key.encrypt(plain_text, 32)[0]).decode('utf-8')

    def decrypt(self, cipher_text):
        cipher_text = base64.b64decode(cipher_text.encode('utf-8'))
        plain_text = self.__key.decrypt(cipher_text)
        return plain_text

    def sign(self, message):
        h = Hash.SHA.new(message.encode('utf-8')).digest()
        return self.__key.sign(h, 32)

    def verify(self, message, signature):
        h = Hash.SHA.new(message.encode('utf-8')).digest()
        return self.__key.verify(h, signature)

    def __import_rsa_key(self, file_path, passphrase=None):
        try:
            f = open(file_path, 'r')
            rsa_byte = f.read()
            rsa_key = RSA.importKey(rsa_byte, passphrase=passphrase)
        except Exception:
            raise Exception(
                'The specified file [' + file_path + '] does not exist or does not contain a valid RSA Key in bytes format')
        return rsa_key

    def __generate_rsa_key(self, size=1024, output_file=None, passphrase=None):
        rsa_key = RSA.generate(int(size))
        if output_file is not None:
            f = open(output_file, 'w')
            f.write(rsa_key.exportKey(format='PEM', passphrase=passphrase).decode())
        return rsa_key
