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


if __name__ == '__main__':
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
        print("Au revoir :)")
