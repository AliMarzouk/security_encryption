import hashlib
import random
import base64

from crypto.Cipher import *
from time import time
from string import printable
from itertools import product, count

def encodeBase64(message):
    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message

def decodeBase64(base64_message):
    base64_bytes = base64_message.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return message

def getHasher(hash_type):
    assert hash_type in AvailableHashAlgorithms()
    hasher= getattr(hashlib,hash_type)
    return hasher

def hash_message(message,hash_type):
    hasher=getHasher(hash_type)
    return hasher(message.encode('ascii')).digest()

def AvailableHashAlgorithms():
    return hashlib.algorithms_available

def passwords(encoding):
    chars = [c.encode(encoding) for c in printable]
    for length in count(start=1):
        for pwd in product(chars, repeat=length):
            yield b''.join(pwd)

def crack_brute_force(user_hash, hash_type, encoding='ascii', verbose=False):
    print('[*] searching of hash by brute force')
    f = open("tested_brute_force.txt", "w")
    h = getHasher(hash_type)
    start = time()
    count=0
    for pwd in passwords(encoding):
        count = count + 1
        if verbose:
            f.write('\n ' +str(pwd))
            f.flush()
        if str(h(pwd).digest()) == str(user_hash):
            end = time()
            print ("\n[+] Hash is: %s" % pwd)
            print ("[*] Words tried: %s" % count)
            print ("[*] Time: %s seconds" % round((end - start), 2))
            f.close()
            return pwd.decode(encoding)

def crack_dictionnary(userHash,hash_type,file_path,encoding='ascii'):
    print('[*] searching of hash in dictionnary')
    h = getHasher(hash_type)
    start = time()
    lineCount = 0
    with open(file_path, "r") as infile:
        for line in infile:
            line = line.strip()
            lineHash = h(line.encode(encoding)).digest()

            if str(lineHash) == str(userHash):
                end = time()
                print ("\n[+] Hash is: %s" % line)
                print ("[*] Words tried: %s" % lineCount)
                print ("[*] Time: %s seconds" % round((end - start), 2))
                return line
            else:
                lineCount = lineCount + 1
        print('[x] No match found')

def generateSalt(length):
    ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    salt=''
    for i in range(length):
        salt = salt + random.choice(ALPHABET)
    return salt

def pad8(msg):
    toAdd = 0
    if len(msg) % 8 != 0:
        toAdd = 8 - len(msg) % 8
    return msg + ' ' * (toAdd)

def pad16(msg):
    toAdd = 0
    if len(msg) % 16 != 0:
        toAdd = 16 - len(msg) % 16
    return msg + ' ' * (toAdd)

def DESencrypt(plain_text, password, generate_salt=False):
    
    plain_text = pad8(plain_text)
    salt=''
    if (generate_salt):
        salt = generateSalt(DES.block_size)

        
    private_key = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=2**14, r=8, p=1, dklen=8)

    
    cipher_config = DES.new(private_key, AES.MODE_ECB)

    
    cipher_text = cipher_config.encrypt(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'salt': base64.b64encode(salt.encode('utf-8')).decode('utf-8')
    }

def DESdecrypt(cipher_text, password,salt=''):
    
    salt = base64.b64decode(salt)
    cipher_text = base64.b64decode(cipher_text)
    
    
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=8)

    
    cipher = DES.new(private_key, AES.MODE_ECB)

    
    decrypted = cipher.decrypt(cipher_text)

    return decrypted

def AESencrypt(plain_text, password, generate_salt=False):
    
    plain_text = pad16(plain_text)
    salt=''
    if (generate_salt):
        salt = generateSalt(DES.block_size)

        
    private_key = hashlib.scrypt(
        password.encode(), salt=salt.encode(), n=2**14, r=8, p=1, dklen=32)

    
    cipher_config = AES.new(private_key, AES.MODE_ECB)

    
    cipher_text = cipher_config.encrypt(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'salt': base64.b64encode(salt.encode('utf-8')).decode('utf-8')
    }

def AESdecrypt(cipher_text, password,salt=''):
    
    salt = base64.b64decode(salt)
    cipher_text = base64.b64decode(cipher_text)
    
    
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    
    cipher = AES.new(private_key, AES.MODE_ECB)

    
    decrypted = cipher.decrypt(cipher_text)

    return decrypted

#algo_number = 1 : DES
#algo_number = 2 : AES
def sym_encryption(algo_number,plain_text, password, generate_salt=False):
    if (algo_number == 1):
        return DESencrypt(plain_text, password, generate_salt)
    elif (algo_number == 2):
        return AESencrypt(plain_text, password, generate_salt)
    else:
        raise AssertionError 


#algo_number = 1 : DES
#algo_number = 2 : AES
def sym_decryption(algo_number,cipher_text, password,salt=''):
    if (algo_number == 1):
        return DESdecrypt(cipher_text, password,salt)
    elif (algo_number == 2):
        return AESdecrypt(cipher_text, password,salt)
    else:
        raise AssertionError
