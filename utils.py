import hashlib
import random
import base64

from Crypto.Cipher import *
from time import time
from string import printable
from itertools import product, count


def encode_base64(message):
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message


def decode_base64(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return message


def get_hash(hash_type):
    assert hash_type in available_hash_algorithms()
    hash_fct = getattr(hashlib, hash_type)
    return hash_fct


def hash_message(message, hash_type):
    hash_fct = get_hash(hash_type)
    return hash_fct(message.encode('ascii')).hexdigest()


def available_hash_algorithms():
    return hashlib.algorithms_available


def passwords(encoding):
    chars = [c.encode(encoding) for c in printable]
    for length in count(start=1):
        for pwd in product(chars, repeat=length):
            yield b''.join(pwd)


def crack_brute_force(user_hash, hash_type, encoding='ascii', verbose=False):
    print('[*] Tentative de craquer le hachage par force brute...')
    f = open("tested_brute_force.txt", "w")
    h = get_hash(hash_type)
    start = time()
    counter = 0
    for pwd in passwords(encoding):
        counter = counter + 1
        if verbose:
            f.write('\n ' + str(pwd))
            f.flush()
        if str(h(pwd).hexdigest()) == str(user_hash):
            end = time()
            print("\n[+] Le mot haché est: %s" % pwd)
            print("[*] Nombre d'essais: %s" % counter)
            print("[*] Temps écoulé: %s secondes" % round((end - start), 2))
            f.close()
            return pwd.decode(encoding)


def crack_dictionary(user_hash, hash_type, file_path, encoding='ascii'):
    print('[*] Tentative de craquer le hachage par dictionnaire...')
    h = get_hash(hash_type)
    start = time()
    line_count = 0
    with open(file_path, "r") as infile:
        for line in infile:
            line = line.strip()
            line_hash = h(line.encode(encoding)).hexdigest()
            line_count = line_count + 1
            if str(line_hash) == str(user_hash):
                end = time()
                print("\n[+] Le mot haché est: %s" % line)
                print("[*] Nombre d'essais: %s" % line_count)
                print("[*] Temps écoulé: %s secondes" % round((end - start), 2))
                return line
        print('[x] Pas de résultat trouvé')


def generate_salt(length):
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    salt = ''
    for i in range(length):
        salt = salt + random.choice(alphabet)
    return salt


def pad8(msg):
    to_add = 0
    if len(msg) % 8 != 0:
        to_add = 8 - len(msg) % 8
    return msg + ' ' * to_add


def pad16(msg):
    to_add = 0
    if len(msg) % 16 != 0:
        to_add = 16 - len(msg) % 16
    return msg + ' ' * to_add


def des_encrypt(plain_text, password, with_salt=False):
    plain_text = pad8(plain_text)
    salt = ''
    if with_salt:
        salt = generate_salt(DES.block_size)

    private_key = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=2 ** 14, r=8, p=1, dklen=8)

    cipher_config = DES.new(private_key, AES.MODE_ECB)

    cipher_text = cipher_config.encrypt(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'salt': base64.b64encode(salt.encode('utf-8')).decode('utf-8')
    }


def des_decrypt(cipher_text, password, salt=''):
    salt = base64.b64decode(salt)
    cipher_text = base64.b64decode(cipher_text)

    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=8)

    cipher = DES.new(private_key, AES.MODE_ECB)

    decrypted = cipher.decrypt(cipher_text)

    return decrypted


def aes_encrypt(plain_text, password, with_salt=False):
    plain_text = pad16(plain_text)
    salt = ''
    if with_salt:
        salt = generate_salt(DES.block_size)

    private_key = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=2 ** 14, r=8, p=1, dklen=32)

    cipher_config = AES.new(private_key, AES.MODE_ECB)

    cipher_text = cipher_config.encrypt(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'salt': base64.b64encode(salt.encode('utf-8')).decode('utf-8')
    }


def aes_decrypt(cipher_text, password, salt=''):
    salt = base64.b64decode(salt)
    cipher_text = base64.b64decode(cipher_text)

    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)

    cipher = AES.new(private_key, AES.MODE_ECB)

    decrypted = cipher.decrypt(cipher_text)

    return decrypted


# algo_number = 1 : DES
# algo_number = 2 : AES
def sym_encryption(algo_number, plain_text, password, with_salt=False):
    if algo_number == 1:
        return des_encrypt(plain_text, password, with_salt)
    elif algo_number == 2:
        return aes_encrypt(plain_text, password, with_salt)
    else:
        raise AssertionError

    # algo_number = 1 : DES


# algo_number = 2 : AES
def sym_decryption(algo_number, cipher_text, password, salt=''):
    if algo_number == 1:
        return des_decrypt(cipher_text, password, salt)
    elif algo_number == 2:
        return aes_decrypt(cipher_text, password, salt)
    else:
        raise AssertionError
