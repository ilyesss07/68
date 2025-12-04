# 68

import random
import hashlib
import os

# ==============================================================================
# 🛡️ TP1 : CHIFFREMENT SYMÉTRIQUE
# ==============================================================================

def chiffre_cesar(message, decalage):
    """
    Chiffre un message avec le code de César.
    Paramètre réaliste : un texte en français et un décalage entier (ex: 3).
    """
    resultat = ""
    for lettre in message:
        if lettre.isalpha():
            # Gestion des majuscules et minuscules
            base = ord('A') if lettre.isupper() else ord('a')
            # Formule : (Position + Décalage) % 26
            chiffre = (ord(lettre) - base + decalage) % 26
            resultat += chr(base + chiffre)
        else:
            # On ne touche pas à la ponctuation
            resultat += lettre
    return resultat

def casser_cesar(message_chiffre):
    """
    Casse le code par analyse fréquentielle (la lettre 'e' est la plus fréquente).
    """
    frequences = {}
    for lettre in message_chiffre:
        if lettre.isalpha():
            char = lettre.lower()
            frequences[char] = frequences.get(char, 0) + 1
    
    if not frequences: return "Message vide"

    # Trouver la lettre la plus fréquente (supposée être 'e')
    lettre_max = max(frequences, key=frequences.get)
    
    # 'e' est à l'index 4. On calcule le décalage entre la lettre trouvée et 'e'.
    # Si 'h' (index 7) est la plus fréquente, le décalage probable est 7 - 4 = 3.
    decalage_estime = (ord(lettre_max) - ord('e')) % 26
    
    print(f"[César] Lettre la plus fréquente : '{lettre_max}'. Décalage détecté : {decalage_estime}")
    return chiffre_cesar(message_chiffre, -decalage_estime)

def xor_chiffrement_bloc(donnees, cle):
    """
    Simule un chiffrement par bloc (type AES/OTP) avec un XOR.
    Paramètre réaliste : contenu binaire d'un fichier et une clé textuelle.
    """
    resultat = bytearray()
    cle_bytes = cle.encode('utf-8')
    len_cle = len(cle_bytes)
    
    for i, octet in enumerate(donnees):
        resultat.append(octet ^ cle_bytes[i % len_cle])
    return resultat

# ==============================================================================
# 🔑 TP2 : CHIFFREMENT ASYMÉTRIQUE (RSA)
# ==============================================================================

# Outils Mathématiques nécessaires pour RSA
def pgcd(a, b):
    while b:
        a, b = b, a % b
    return a

def euclide_etendu(a, b):
    """Retourne (g, x, y) tels que ax + by = g"""
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = euclide_etendu(b % a, a)
        return g, x - (b // a) * y, y

def inverse_modulaire(e, phi):
    """Calcule d tel que (d * e) % phi == 1"""
    g, x, y = euclide_etendu(e, phi)
    if g != 1:
        raise Exception("L'inverse modulaire n'existe pas")
    return x % phi

def est_premier(n, k=5):
    """Test de primalité de Miller-Rabin (pour générer de grands nombres)."""
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generer_premier(bits):
    """Génère un nombre premier de la taille spécifiée (ex: 16 bits)."""
    while True:
        n = random.getrandbits(bits)
        if n % 2 == 0: n += 1
        if est_premier(n):
            return n

def generer_cles_rsa(taille_bits=16):
    """
    Génère des clés RSA réalistes (pour un TP).
    taille_bits=16 permet d'avoir des nombres ~30 000-60 000, 
    suffisants pour chiffrer des blocs ASCII.
    """
    p = generer_premier(taille_bits)
    q = generer_premier(taille_bits)
    while p == q:
        q = generer_premier(taille_bits)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537 # Valeur standard pour la clé publique
    if pgcd(e, phi) != 1:
        e = 3
        while pgcd(e, phi) != 1:
            e += 2
            
    d = inverse_modulaire(e, phi)
    return ((e, n), (d, n))

def chiffrer_rsa(message_int, cle_publique):
    e, n = cle_publique
    return pow(message_int, e, n)

def dechiffrer_rsa(chiffre_int, cle_privee):
    d, n = cle_privee
    return pow(chiffre_int, d, n)

# ==============================================================================
# 📡 TP3 : INTÉGRITÉ ET CODES CORRECTEURS
# ==============================================================================

def calcul_crc(message_binaire, generateur):
    """
    Calcul du CRC (reste de la division polynomiale).
    Paramètre réaliste : "11101" et "1011" (z^3 + x + 1).
    """
    n = len(generateur) - 1
    # Padding : ajout de zéros à la fin
    donnees = list(message_binaire + '0' * n)
    diviseur = list(generateur)
    
    for i in range(len(message_binaire)):
        if donnees[i] == '1':
            for j in range(len(diviseur)):
                # XOR
                donnees[i + j] = str(int(donnees[i + j]) ^ int(diviseur[j]))
    
    reste = "".join(donnees)[-n:]
    return message_binaire + reste

def hash_sha256(texte):
    """Hashage sécurisé standard."""
    return hashlib.sha256(texte.encode()).hexdigest()

def hamming_7_4_encode(bits_4):
    """Encode 4 bits de données en 7 bits (Hamming)."""
    d = [int(b) for b in bits_4] # d1, d2, d3, d4
    
    # Calcul des parités (p1, p2, p3)
    p1 = d[0] ^ d[1] ^ d[3]
    p2 = d[0] ^ d[2] ^ d[3]
    p3 = d[1] ^ d[2] ^ d[3]
    
    # Ordre standard : p1 p2 d1 p3 d2 d3 d4
    return f"{p1}{p2}{d[0]}{p3}{d[1]}{d[2]}{d[3]}"

def hamming_7_4_decode(bits_7):
    """Corrige une erreur éventuelle sur 7 bits."""
    b = [int(x) for x in bits_7]
    
    # Calcul du syndrome
    c1 = b[0] ^ b[2] ^ b[4] ^ b[6] # Vérifie 1,3,5,7
    c2 = b[1] ^ b[2] ^ b[5] ^ b[6] # Vérifie 2,3,6,7
    c3 = b[3] ^ b[4] ^ b[5] ^ b[6] # Vérifie 4,5,6,7
    
    pos_erreur = c3 * 4 + c2 * 2 + c1
    
    if pos_erreur != 0:
        print(f"[Hamming] Erreur détectée et corrigée à la position {pos_erreur}")
        b[pos_erreur - 1] = 1 - b[pos_erreur - 1] # Inversion du bit
    else:
        print("[Hamming] Aucune erreur détectée.")
        
    return f"{b[2]}{b[4]}{b[5]}{b[6]}" # Retourne les données d1d2d3d4

# ==============================================================================
# 🚀 EXÉCUTION DES TESTS AVEC PARAMÈTRES RÉALISTES
# ==============================================================================

if __name__ == "__main__":
    print("\n--- TEST TP1 : SYMETRIQUE ---")
    # Paramètres réalistes : Une vraie phrase et un décalage classique
    phrase_claire = "La cryptographie est fascinante"
    decalage = 5
    
    crypte = chiffre_cesar(phrase_claire, decalage)
    print(f"Original : {phrase_claire}")
    print(f"Chiffré  : {crypte}")
    print(f"Cassé    : {casser_cesar(crypte)}")
    
    # Simulation fichier : création d'un fichier test
    nom_fichier = "secret_tp1.txt"
    cle_secrete = "MaCleSecrete123"
    with open(nom_fichier, "w") as f: f.write("Ceci est le contenu d'un fichier confidentiel.")
    
    # Lecture/Ecriture binaire pour simuler le chiffrement de fichier
    with open(nom_fichier, "rb") as f: data = f.read()
    data_enc = xor_chiffrement_bloc(data, cle_secrete)
    print(f"\n[Fichier] Données chiffrées (hex) : {data_enc.hex()[:30]}...")
    data_dec = xor_chiffrement_bloc(data_enc, cle_secrete)
    print(f"[Fichier] Données déchiffrées : {data_dec.decode()}")

    print("\n--- TEST TP2 : RSA ---")
    # Paramètres réalistes : Génération de clés sur 16 bits (suffisant pour encoder des blocs de texte)
    # Dans la vraie vie, on utiliserait 2048 bits.
    pub, priv = generer_cles_rsa(taille_bits=16)
    print(f"Clé Publique (e, n) : {pub}")
    print(f"Clé Privée   (d, n) : {priv}")
    
    message_tp2 = "RSA"
    # On chiffre chaque caractère séparément (approche naïve réaliste pour un TP)
    msg_chiffre = [chiffrer_rsa(ord(c), pub) for c in message_tp2]
    print(f"Message '{message_tp2}' chiffré : {msg_chiffre}")
    
    msg_dechiffre = "".join([chr(dechiffrer_rsa(c, priv)) for c in msg_chiffre])
    print(f"Message déchiffré : {msg_dechiffre}")

    print("\n--- TEST TP3 : INTÉGRITÉ ---")
    # 1. CRC : Exemple exact du PDF TP3
    msg_bin = "11101"
    poly = "1011" # z^3 + x + 1
    crc_resultat = calcul_crc(msg_bin, poly)
    print(f"CRC ({msg_bin} / {poly}) : {crc_resultat} (Devrait être 11101000)")
    
    # 2. Hachage : Mot de passe réaliste
    mdp = "MotDePasseSuperSecurise!"
    print(f"SHA-256 ('{mdp}') : {hash_sha256(mdp)}")
    
    # 3. Hamming : Donnée 4 bits standard
    data_bits = "1011"
    encoded = hamming_7_4_encode(data_bits)
    print(f"Hamming Encodé ({data_bits}) : {encoded}")
    
    # Simulation d'erreur : on corrompt le 3ème bit (index 2)
    # '1' devient '0' ou '0' devient '1'
    liste_bits = list(encoded)
    liste_bits[2] = '0' if liste_bits[2] == '1' else '1'
    corrupted = "".join(liste_bits)
    print(f"Message reçu (corrompu)  : {corrupted}")
    
    decoded = hamming_7_4_decode(corrupted)
    print(f"Message corrigé et décodé : {decoded}")
