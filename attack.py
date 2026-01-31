#!/usr/bin/env python3
import json
import secrets
import hashlib
import sys

# Importation des primitives fournies dans ton fichier ec_utils.py
from ec_utils import (
    N, G, Point,
    point_multiply, point_add, mod_inverse
)

def load_firmwares(filename):
    with open(filename, 'r') as f:
        return json.load(f)

# ==============================================================================
# PHASE 1 : Implémentation ECDSA (Signature et Vérification)
# ==============================================================================

def ecdsa_sign(message_bytes, private_key_d):
    """ Signe un message. Si k n'est pas fourni, on le génère aléatoirement. """
    # 1. Hachage du message (SHA-1 utilisé par la PS3)
    h = hashlib.sha1(message_bytes).hexdigest()
    e = int(h, 16)

    while True:
        # 2. Génération d'un nonce k aléatoire (C'est ce que Sony a raté !)
        k = secrets.randbelow(N - 1) + 1

        # 3. Calcul du point R = k * G
        R = point_multiply(k, G)
        r = R.x % N

        if r == 0: continue # Cas extrêmement rare

        # 4. Calcul de s = k^(-1) * (e + r*d) mod n
        k_inv = mod_inverse(k, N)
        s = (k_inv * (e + r * private_key_d)) % N

        if s == 0: continue

        return (r, s)

def ecdsa_verify(message_bytes, signature, public_key_point):
    """ Vérifie une signature (r, s) pour un message donné """
    r, s = signature

    if not (1 <= r < N) or not (1 <= s < N):
        return False

    # 1. Hachage
    h = hashlib.sha1(message_bytes).hexdigest()
    e = int(h, 16)

    # 2. Inversion de s
    w = mod_inverse(s, N)

    # 3. Calcul des coefficients u1 et u2
    u1 = (e * w) % N
    u2 = (r * w) % N

    # 4. Calcul du point R' = u1*G + u2*Q
    point_1 = point_multiply(u1, G)
    point_2 = point_multiply(u2, public_key_point)
    R_prime = point_add(point_1, point_2)

    if R_prime is None:
        return False

    # 5. Vérification
    return (R_prime.x % N) == r

# ==============================================================================
# PHASE 2 : Détection de la faille (Nonce Reuse)
# ==============================================================================

def find_collision(firmwares):
    """ Cherche deux firmwares ayant le même 'r' """
    seen_r = {}
    for fw in firmwares:
        r = fw['signature']['r'] # C'est une string hex "0x..."
        if r in seen_r:
            return seen_r[r], fw
        seen_r[r] = fw
    return None, None

# ==============================================================================
# PHASE 3 : L'Attaque Mathématique (Retrouver la clé privée)
# ==============================================================================

def recover_private_key(fw1, fw2):
    """
    Retrouve la clé privée d à partir de deux signatures utilisant le même k.
    Mathématiques :
    s1 = k^-1 (e1 + r*d)
    s2 = k^-1 (e2 + r*d)

    (s1 - s2) = k^-1 (e1 - e2)  =>  k = (e1 - e2) / (s1 - s2)
    Une fois k connu : d = (s1 * k - e1) / r
    """

    # Conversion des valeurs hexadécimales en entiers
    r  = int(fw1['signature']['r'], 16)
    s1 = int(fw1['signature']['s'], 16)
    e1 = int(fw1['hash'], 16)

    s2 = int(fw2['signature']['s'], 16)
    e2 = int(fw2['hash'], 16)

    # 1. Calcul du nonce k
    # k = (e1 - e2) * (s1 - s2)^(-1) mod N
    numerator = (e1 - e2) % N
    denominator = (s1 - s2) % N
    den_inv = mod_inverse(denominator, N)

    k = (numerator * den_inv) % N

    print(f" -> Nonce k retrouvé : {hex(k)}")

    # 2. Calcul de la clé privée d
    # d = r^(-1) * (k * s1 - e1) mod N
    r_inv = mod_inverse(r, N)
    term = (k * s1 - e1) % N
    d = (r_inv * term) % N

    return d

# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == "__main__":
    print("--- DÉBUT DE L'OPÉRATION FAIL0VERFLOW ---\n")

    # 1. Chargement des données
    data = load_firmwares("firmwares.json")
    print(f"[*] {len(data['firmwares'])} firmwares chargés.")

    # Récupération de la clé publique officielle de Sony pour vérifier notre succès
    sony_pub_x = int(data['public_key']['x'], 16)
    sony_pub_y = int(data['public_key']['y'], 16)
    sony_pub_key = Point(sony_pub_x, sony_pub_y)

    # 2. Détection
    print("\n[*] Recherche de collisions de nonce (valeur r identique)...")
    fw1, fw2 = find_collision(data['firmwares'])

    if fw1 and fw2:
        print(f" -> COLLISION TROUVÉE !")
        print(f"    FW A: v{fw1['version']} (r={fw1['signature']['r'][:10]}...)")
        print(f"    FW B: v{fw2['version']} (r={fw2['signature']['r'][:10]}...)")
    else:
        print("Aucune collision trouvée. Fin.")
        sys.exit()

    # 3. Attaque
    print("\n[*] Calcul de la clé privée...")
    d_found = recover_private_key(fw1, fw2)
    print(f" -> CLÉ PRIVÉE (d) : {hex(d_found)}")

    # Vérification : Est-ce que d * G donne la clé publique de Sony ?
    Q_check = point_multiply(d_found, G)
    if Q_check.x == sony_pub_x and Q_check.y == sony_pub_y:
        print(" -> VÉRIFICATION RÉUSSIE : La clé privée correspond à la clé publique !")
    else:
        print(" -> ERREUR : La clé dérivée est incorrecte.")
        sys.exit()

    # 4. Forge (Création du Homebrew)
    print("\n[*] Création d'un Homebrew signé (Jailbreak)...")
    homebrew_code = b"fail0verflow says: Hello World!"
    print(f"    Message : {homebrew_code}")

    # Signature avec la clé volée
    r_forge, s_forge = ecdsa_sign(homebrew_code, d_found)

    print(f"    Signature générée :")
    print(f"      r: {hex(r_forge)}")
    print(f"      s: {hex(s_forge)}")

    # Vérification finale (comme le ferait la PS3)
    is_valid = ecdsa_verify(homebrew_code, (r_forge, s_forge), sony_pub_key)

    if is_valid:
        print("\n[SUCCESS] Le homebrew est accepté comme valide par la console !")
    else:
        print("\n[FAIL] La signature est invalide.")
