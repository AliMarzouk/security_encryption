from os import system, name
from AsymmetricalEncryption import *
from utils import *
from getpass import getpass


def clear():
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def print_title():
    print(" ---------------------------------------------------")
    print("|                                                   |")
    print("|                  OUTIL SSI INSAT                  |")
    print("|                      POUR LA                      |")
    print("|                   CRYPTOGRAPHIE                   |")
    print("|                                                   |")
    print(" ---------------------------------------------------\n\n")


def print_options():
    print("---------------------------------------------------")
    print("1. Codage et décodage d'un message")
    print("2. Hashage d'un message")
    print("3. Craquage d'un message hashé")
    print("4. Chiffrement et déchiffrement symétrique")
    print("5. Chiffrement et déchiffrement asymétrique")
    print("6. Quitter")
    print("---------------------------------------------------")
    while True:
        try:
            choice = int(input("[*] Votre choix: "))
        except ValueError:
            print("[*] Veuillez saisir un chiffre entre 1 et 6")
        else:
            if 6 >= choice >= 1:
                break
            else:
                print("[*] Veuillez saisir un chiffre entre 1 et 6")
    return choice


def encode_decode():
    print_title()
    print("---------------------------------------------------")
    print("1. Coder un message")
    print("2. Décoder un message")
    print("---------------------------------------------------")
    choice = int(input("[*] Votre choix: "))
    while choice > 2 or choice < 1:
        choice = int(input("[*] Veuillez saisir un choix valide: "))
    clear()
    if choice == 1:
        print_title()
        print("---------------------------------------------------")
        message = input("[*] Veuillez saisir votre message: ")
        print("[*] Le message codé est:")
        print(encode_base64(message))
        print("---------------------------------------------------")
    elif choice == 2:
        print_title()
        print("---------------------------------------------------")
        message = input("[*] Veuillez saisir le message codé: ")
        print("[*] Tentative de décodage...")
        try:
            decrypted_message = decode_base64(message)
            print("[+] Le message est:")
            print(decrypted_message)
        except Exception:
            print("[*] Le message que vous avez saisi n'est pas valide")
        print("---------------------------------------------------")
    input("Tapez sur ENTR pour continuer...")


def hash_choice():
    print_title()
    print("---------------------------------------------------")
    print("[*] Veuillez choisir la fonction de hashage")
    print("[*] "+", ".join(available_hash_algorithms()))
    hash_function = input("[*] Votre choix: ")
    print("---------------------------------------------------")
    while not (hash_function in available_hash_algorithms()):
        print("[*] Veuillez choisir une fonction de hashage valide")
        print(", ".join(available_hash_algorithms()))
        hash_function = input("[*] Votre choix: ")
        print("---------------------------------------------------")
    print("[*] Veuillez saisir votre message:")
    message = input()
    print("---------------------------------------------------")
    print("[+] Output:")
    print(hash_message(message, hash_function))
    print("---------------------------------------------------")
    input("Tapez sur ENTR pour continuer...")


def crack_hash():
    print_title()
    print("---------------------------------------------------")
    print("[*] Veuillez choisir la fonction de hashage")
    print("[*] " + ", ".join(available_hash_algorithms()))
    hash_function = input("[*] Votre choix: ")
    print("---------------------------------------------------")
    while not (hash_function in available_hash_algorithms()):
        print("[*] Veuillez choisir une fonction de hashage valide")
        print(", ".join(available_hash_algorithms()))
        hash_function = input("[*] Votre choix: ")
        print("---------------------------------------------------")
    print("[*] Veuillez saisir le message hashé:")
    message = input()
    print("---------------------------------------------------")
    print("1. Attaque par dictionnaire")
    print("2. Attaque par force brute")
    choice = int(input("[*] Veuillez choisir le type d'attaque: "))
    while choice > 2 or choice < 1:
        choice = int(input("[*] Veuillez saisir un choix valide: "))
    if choice == 1:
        while True:
            try:
                file_path = input("[*] Veuillez saisir le chemin de votre dictionnaire: ")
                open(file_path, "r").close()
            except FileNotFoundError:
                print("[*] Fichier introuvable. Veuillez réessayer...")
            else:
                break
        print("---------------------------------------------------")
        crack_dictionary(message, hash_function, file_path)
    elif choice == 2:
        response = input("[*] Verbose? [O/n]: ")
        verbose = response.upper() == "O"
        print("---------------------------------------------------")
        crack_brute_force(message, hash_function, 'ascii', verbose)
    print("---------------------------------------------------")
    input("Tapez sur ENTR pour continuer...")


def symmetric_encrypt():
    print_title()
    print("---------------------------------------------------")
    print("1. Chiffrement")
    print("2. Déchiffrement")
    choice = int(input("[*] Votre choix: "))
    while choice > 2 or choice < 1:
        choice = int(input("[*] Veuillez saisir un choix valide: "))
    clear()
    print_title()
    print("---------------------------------------------------")
    print("1. DES")
    print("2. AES")
    algorithm = int(input("[*] Votre choix: "))
    while algorithm > 2 or algorithm < 1:
        algorithm = int(input("[*] Veuillez saisir un choix valide: "))
    print("---------------------------------------------------")
    if choice == 1:
        while True:
            print("[*] Veuillez saisir un mot de passe:")
            password = getpass()
            print("[*] Veuillez confirmer le mot de passe:")
            confirm_pwd = getpass()
            if password == confirm_pwd:
                break
            else:
                print("[*] Les mots de passe ne sont pas identiques. Veuillez réessayer...")
        print("---------------------------------------------------")
        print("[*] Veuillez saisir votre message:")
        message = input()
        print("---------------------------------------------------")
        response = input("[*] Voulez-vous ajouter du sel? [O/n]: ")
        salt = response.upper() == "O"
        print("---------------------------------------------------")
        values = sym_encryption(algorithm, message, password, salt)
        print("[+] Message chiffré:")
        print(values['cipher_text'])
        if salt:
            print("[+] Sel:")
            print(values['salt'])
    elif choice == 2:
        print("[*] Veuillez saisir le message à déchiffrer: ")
        message = input()
        print("---------------------------------------------------")
        print("[*] Veuillez saisir votre mot de passe: ")
        password = getpass()
        print("---------------------------------------------------")
        salt = input("[*] Veuillez saisir le sel: ")
        print("---------------------------------------------------")
        print("[*] Tentative de déchiffrement...")
        try:
            value = sym_decryption(algorithm, message, password, salt)
            print("[+] Message déchiffré:")
            print(value.decode('utf-8'))
        except Exception:
            print("[*] Impossible de déchiffrer le message. Veuillez vous assurer que vous avez choisi le bon "
                  "algorithme.")
    print("---------------------------------------------------")
    input("Tapez sur ENTR pour continuer...")


def asymmetric_encrypt():
    print_title()
    print("---------------------------------------------------")
    print("1. Générer une clef")
    print("2. Importer une clef")
    while True:
        try:
            choice = int(input("[*] Votre choix: "))
        except ValueError:
            print("[*] Veuillez saisir un chiffre entre 1 et 2")
        else:
            if 2 >= choice >= 1:
                break
            else:
                print("[*] Veuillez saisir un chiffre entre 1 et 2")
    clear()
    print_title()
    print("---------------------------------------------------")
    print("1. ElGamal")
    print("2. RSA")
    while True:
        try:
            algorithm = int(input("[*] Veuillez choisir un algorithme: "))
        except ValueError:
            print("[*] Veuillez saisir un chiffre entre 1 et 2")
        else:
            if 2 >= algorithm >= 1:
                break
            else:
                print("[*] Veuillez saisir un chiffre entre 1 et 2")
    clear()
    print_title()
    print("---------------------------------------------------")
    if algorithm == 1:
        key = get_el_gamal_key(choice)
    else:
        key = get_rsa_key(choice)
    choice = 0
    while choice != 4:
        clear()
        print_title()
        print("---------------------------------------------------")
        print("1. Chiffrer un message")
        print("2. Déchiffrer un message")
        print("3. Exporter votre clef")
        print("4. Retour au menu principal")
        while True:
            try:
                choice = int(input("[*] Votre choix: "))
            except ValueError:
                print("[*] Veuillez saisir un chiffre entre 1 et 3")
            else:
                if 4 >= choice >= 1:
                    break
                else:
                    print("[*] Veuillez saisir un chiffre entre 1 et 3")
        clear()
        print_title()
        if choice == 1:
            print("---------------------------------------------------")
            print("[*] Veuillez saisir votre message:")
            message = input()
            print("---------------------------------------------------")
            print("[+] Message chiffré:")
            print(key.encrypt(message))
        if choice == 2:
            if key.is_private():
                decrypt(key, algorithm)
            else:
                print("Votre clef ne possède pas une composante privée. Impossible d'éffectuer un déchiffrement")
        print("---------------------------------------------------")
        input("Tapez sur ENTR pour continuer...")


def decrypt(key, algorithm):
    if algorithm == 1:
        print("---------------------------------------------------")
        print("[*] Veuillez saisir le premier morceau:")
        u = input()
        print("[*] Veuillez saisir le deuxième morceau:")
        v = input()
        print("---------------------------------------------------")
        print("Tentative de déchiffrement...")
        message = key.decrypt([u, v])
        print("[+] Message déchiffré:")
        print(message)
    elif algorithm == 2:
        print("---------------------------------------------------")
        print("[*] Veuillez saisir le message à déchiffrer:")
        text = input()
        print("---------------------------------------------------")
        print("Tentative de déchiffrement...")
        try:
            message = key.decrypt(text)
            print("[+] Message déchiffré:")
            print(message)
        except Exception:
            print("[*] La tentative de déchiffrement a échoué.")

def get_el_gamal_key(choice):
    key = ElGamalEncryption()
    if choice == 1:
        while True:
            try:
                size = int(input("[*] Veuillez saisir la taille de votre clef: "))
            except ValueError:
                print("[*] Veuillez saisir un nombre valide")
            else:
                break
        key.generate_key(size)
    if choice == 2:
        while True:
            try:
                p = int(input("[*] Veuillez saisir le module p: "))
            except ValueError:
                print("[*] Veuillez saisir un nombre valide")
            else:
                break
        print("---------------------------------------------------")
        while True:
            try:
                g = int(input("[*] Veuillez saisir le générateur g: "))
            except ValueError:
                print("[*] Veuillez saisir un nombre valide")
            else:
                break
        print("---------------------------------------------------")
        while True:
            try:
                y = int(input("[*] Veuillez saisir votre clef publique y: "))
            except ValueError:
                print("[*] Veuillez saisir un nombre valide")
            else:
                break
        print("---------------------------------------------------")
        while True:
            try:
                x = int(input("[*] Veuillez saisir votre clef privée x (Laissez ce champ vide s'il sagit d'une clef "
                              "publique): "))
            except ValueError:
                print("[*] Veuillez saisir un nombre valide")
            else:
                break
        if x:
            tup = (p, g, y, x)
        else:
            tup = (p, g, y)
        key.construct_key(tup)
    return key


def get_rsa_key(choice):
    key = RSAEncryption()
    if choice == 1:
        while True:
            try:
                size = int(input("[*] Veuillez saisir la taille de votre clef: "))
            except ValueError:
                print("[*] Veuillez saisir un nombre valide")
            else:
                break
        while True:
            print("[*] Veuillez saisir un mot de passe:")
            password = getpass()
            print("[*] Veuillez confirmer le mot de passe:")
            confirm_pwd = getpass()
            if password == confirm_pwd:
                break
            else:
                print("[*] Les mots de passe ne sont pas identiques. Veuillez réessayer...")
        key.generate_key(size, password)
    elif choice == 2:
        while True:
            while True:
                try:
                    path = input("[*] Veuillez saisir le chemin de votre clef: ")
                    open(path, 'r').close()
                except FileNotFoundError:
                    print("[*] Fichier introuvable. Veuillez réessayer...")
                else:
                    break
            print("[*] Veuillez saisir le mot de passe:")
            password = getpass()
            try:
                key.import_key(path, password)
            except Exception:
                print("[*] Le fichier spécifié n'existe pas ou ne contient pas de clé RSA valide au format octets. "
                      "Veuillez réessayer...")
            else:
                break
    return key


if __name__ == '__main__':
    gamal = ElGamalEncryption()
    gamal.generate_key(23)
    print(gamal.decrypt(gamal.encrypt('test')))
    """
    try:
        while True:
            clear()
            print_title()
            menu_choice = print_options()
            clear()
            if menu_choice == 1:
                encode_decode()
            elif menu_choice == 2:
                hash_choice()
            elif menu_choice == 3:
                crack_hash()
            elif menu_choice == 4:
                symmetric_encrypt()
            elif menu_choice == 5:
                symmetric_encrypt()
            elif menu_choice == 6:
                clear()
                exit()
    except KeyboardInterrupt:
        clear()
        print("Au revoir :)")"""