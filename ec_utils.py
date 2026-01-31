#!/usr/bin/env python3
"""
ec_utils.py - Primitives de courbe elliptique pour le TP fail0verflow

Ce module fournit les opérations de base sur courbes elliptiques
nécessaires pour implémenter et attaquer ECDSA.

COURBE UTILISÉE : VSH Curve (PS3)
Il s'agit de la vraie courbe utilisée par Sony pour signer les
firmwares de la PlayStation 3. C'est une courbe de 160 bits.

Les paramètres ont été extraits du wiki PS3 Dev :
https://www.psdevwiki.com/ps3/Keys
"""

# ============================================================================
# PARAMÈTRES DE LA COURBE VSH (PlayStation 3)
# ============================================================================
#
# La courbe est définie par l'équation :
#     y² ≡ x³ + ax + b  (mod p)
#
# Ces paramètres sont ceux réellement utilisés par Sony.
# C'est une courbe de 160 bits (sécurité ~80 bits).

# Module premier (160 bits)
P = 0xFFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFF

# Coefficient a de la courbe
A = 0xFFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFC

# Coefficient b de la courbe
B = 0xA68BEDC33418029C1D3CE33B9A321FCCBB9E0F0B

# Ordre du groupe (nombre de points sur la courbe)
N = 0xFFFFFFFFFFFFFFFEFFFFB5AE3C523E63944F2127

# Coordonnées du point générateur G
GX = 0x128EC4256487FD8FDF64E2437BC0A1F6D5AFDE2C
GY = 0x5958557EB1DB001260425524DBC379D5AC5F4ADF


# ============================================================================
# ARITHMÉTIQUE MODULAIRE
# ============================================================================

def mod_inverse(a: int, m: int) -> int:
    """
    Calcule l'inverse modulaire de a modulo m.
    
    L'inverse de a modulo m est l'entier x tel que :
        a * x ≡ 1  (mod m)
    
    Utilise l'algorithme d'Euclide étendu.
    
    Args:
        a: L'entier dont on cherche l'inverse
        m: Le module
    
    Returns:
        L'inverse de a modulo m
    
    Raises:
        ValueError: Si a n'a pas d'inverse modulo m (pgcd(a,m) ≠ 1)
    
    Exemple:
        >>> mod_inverse(3, 7)
        5
        >>> (3 * 5) % 7
        1
    """
    if a < 0:
        a = a % m
    
    g, x, _ = _extended_gcd(a, m)
    
    if g != 1:
        raise ValueError(f"Pas d'inverse modulaire pour {a} modulo {m}")
    
    return x % m


def _extended_gcd(a: int, b: int) -> tuple:
    """
    Algorithme d'Euclide étendu.
    
    Calcule le PGCD de a et b, ainsi que les coefficients de Bézout
    x et y tels que : a*x + b*y = pgcd(a, b)
    
    Args:
        a, b: Les deux entiers
    
    Returns:
        (pgcd, x, y) : le PGCD et les coefficients de Bézout
    """
    if a == 0:
        return b, 0, 1
    
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd, x, y


# ============================================================================
# CLASSE POINT
# ============================================================================

class Point:
    """
    Représente un point sur une courbe elliptique.
    
    Un point peut être :
    - Un point régulier avec des coordonnées (x, y)
    - Le "point à l'infini" (élément neutre du groupe), représenté par (None, None)
    
    Attributs:
        x: Coordonnée x du point (ou None pour le point à l'infini)
        y: Coordonnée y du point (ou None pour le point à l'infini)
    
    Exemple:
        >>> P = Point(GX, GY)  # Le point générateur
        >>> O = Point()         # Le point à l'infini
        >>> P.is_infinity()
        False
        >>> O.is_infinity()
        True
    """
    
    def __init__(self, x: int = None, y: int = None):
        """
        Crée un nouveau point.
        
        Args:
            x: Coordonnée x (None pour le point à l'infini)
            y: Coordonnée y (None pour le point à l'infini)
        """
        self.x = x
        self.y = y
    
    def is_infinity(self) -> bool:
        """
        Vérifie si ce point est le point à l'infini.
        
        Le point à l'infini est l'élément neutre du groupe :
        P + O = O + P = P pour tout point P.
        
        Returns:
            True si c'est le point à l'infini
        """
        return self.x is None and self.y is None
    
    def is_on_curve(self) -> bool:
        """
        Vérifie si ce point est sur la courbe VSH.
        
        Un point (x, y) est sur la courbe si :
            y² ≡ x³ + ax + b  (mod p)
        
        Returns:
            True si le point est sur la courbe
        """
        if self.is_infinity():
            return True
        
        left = (self.y * self.y) % P
        right = (self.x**3 + A * self.x + B) % P
        
        return left == right
    
    def __eq__(self, other) -> bool:
        """Vérifie l'égalité de deux points."""
        if other is None:
            return False
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self) -> str:
        """Représentation textuelle du point."""
        if self.is_infinity():
            return "Point(∞)"
        return f"Point(x=0x{self.x:040x}, y=0x{self.y:040x})"
    
    def __str__(self) -> str:
        """Version courte pour l'affichage."""
        if self.is_infinity():
            return "O (point à l'infini)"
        return f"({hex(self.x)[:12]}..., {hex(self.y)[:12]}...)"


# ============================================================================
# OPÉRATIONS SUR LES POINTS
# ============================================================================

def point_add(P1: Point, P2: Point) -> Point:
    """
    Additionne deux points sur la courbe elliptique.
    
    L'addition de points sur une courbe elliptique est définie géométriquement :
    
    1. Si l'un des points est le point à l'infini O :
       P + O = O + P = P
    
    2. Si P1 = -P2 (même x, y opposés) :
       P1 + P2 = O (point à l'infini)
    
    3. Si P1 ≠ P2 (addition de points distincts) :
       - Tracer la droite passant par P1 et P2
       - Cette droite coupe la courbe en un troisième point R
       - Le résultat est -R (symétrique de R par rapport à l'axe x)
       
       Formules :
           λ = (y2 - y1) / (x2 - x1)  mod p
           x3 = λ² - x1 - x2          mod p
           y3 = λ(x1 - x3) - y1       mod p
    
    4. Si P1 = P2 (doublement de point) :
       - Tracer la tangente à la courbe en P1
       - Cette tangente coupe la courbe en un autre point R
       - Le résultat est -R
       
       Formules :
           λ = (3x1² + a) / (2y1)     mod p
           x3 = λ² - 2x1              mod p
           y3 = λ(x1 - x3) - y1       mod p
    
    Args:
        P1: Premier point
        P2: Deuxième point
    
    Returns:
        La somme P1 + P2
    
    Exemple:
        >>> G = Point(GX, GY)
        >>> O = Point()
        >>> point_add(G, O) == G
        True
    """
    # Cas 1 : Un des points est le point à l'infini
    if P1.is_infinity():
        return Point(P2.x, P2.y)
    if P2.is_infinity():
        return Point(P1.x, P1.y)
    
    # Cas 2 : P1 = -P2 (même x, y opposés)
    if P1.x == P2.x and P1.y != P2.y:
        return Point()  # Retourne le point à l'infini
    
    # Cas 3 et 4 : Calcul de la pente λ (lambda)
    if P1.x == P2.x and P1.y == P2.y:
        # Cas 4 : Doublement (P1 = P2)
        # λ = (3x² + a) / (2y)
        numerator = (3 * P1.x * P1.x + A) % P
        denominator = (2 * P1.y) % P
    else:
        # Cas 3 : Addition de points distincts
        # λ = (y2 - y1) / (x2 - x1)
        numerator = (P2.y - P1.y) % P
        denominator = (P2.x - P1.x) % P
    
    # Division modulaire : λ = numerator * denominator^(-1)
    lam = (numerator * mod_inverse(denominator, P)) % P
    
    # Calcul des coordonnées du résultat
    x3 = (lam * lam - P1.x - P2.x) % P
    y3 = (lam * (P1.x - x3) - P1.y) % P
    
    return Point(x3, y3)


def point_multiply(k: int, P: Point) -> Point:
    """
    Multiplication scalaire : calcule k * P.
    
    La multiplication scalaire consiste à additionner un point P
    à lui-même k fois :
        k * P = P + P + ... + P  (k fois)
    
    Utilise l'algorithme "double-and-add" (similaire à l'exponentiation
    rapide) pour calculer efficacement en O(log k) opérations.
    
    Algorithme double-and-add :
        1. Écrire k en binaire : k = k_n k_{n-1} ... k_1 k_0
        2. Initialiser result = O (point à l'infini)
        3. Pour chaque bit de k (du plus significatif au moins significatif) :
           - result = 2 * result  (doublement)
           - Si le bit vaut 1 : result = result + P
        4. Retourner result
    
    Exemple : 13 * P avec 13 = 1101 en binaire
        - bit 1 : result = O, puis result = O + P = P
        - bit 1 : result = 2P, puis result = 2P + P = 3P
        - bit 0 : result = 6P (pas d'addition)
        - bit 1 : result = 12P, puis result = 12P + P = 13P
    
    Args:
        k: Le scalaire (entier positif)
        P: Le point à multiplier
    
    Returns:
        Le point k * P
    
    Exemple:
        >>> G = Point(GX, GY)
        >>> point_multiply(1, G) == G
        True
        >>> point_multiply(N, G).is_infinity()  # N * G = O
        True
    """
    if k == 0:
        return Point()  # 0 * P = O
    
    if k < 0:
        # k négatif : calculer |k| * P puis inverser
        k = -k
        P = Point(P.x, (-P.y) % P)
    
    result = Point()  # Point à l'infini (élément neutre)
    addend = Point(P.x, P.y)  # Copie de P
    
    # Algorithme double-and-add (parcours des bits de droite à gauche)
    while k > 0:
        if k & 1:  # Si le bit de poids faible est 1
            result = point_add(result, addend)
        addend = point_add(addend, addend)  # Doublement
        k >>= 1  # Décalage à droite (division par 2)
    
    return result


def point_negate(pt: Point) -> Point:
    """
    Calcule l'opposé d'un point : -P.
    
    Sur une courbe elliptique, l'opposé de P = (x, y) est -P = (x, -y).
    Géométriquement, c'est le symétrique par rapport à l'axe x.
    
    On a : P + (-P) = O (point à l'infini)
    
    Args:
        pt: Le point à inverser
    
    Returns:
        Le point -P
    """
    if pt.is_infinity():
        return Point()
    
    return Point(pt.x, (-pt.y) % P)


# ============================================================================
# POINT GÉNÉRATEUR
# ============================================================================

# Le point générateur G de la courbe VSH
G = Point(GX, GY)


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def verify_curve_params():
    """
    Vérifie que les paramètres de la courbe sont cohérents.
    
    Returns:
        True si tous les tests passent
    """
    print("Vérification des paramètres de la courbe VSH (PS3)...")
    print(f"  - Module p : {P.bit_length()} bits")
    print(f"  - Ordre n  : {N.bit_length()} bits")
    
    # Vérifier que G est sur la courbe
    assert G.is_on_curve(), "G n'est pas sur la courbe !"
    print("  - G est sur la courbe : ✓")
    
    # Vérifier que n * G = O
    nG = point_multiply(N, G)
    assert nG.is_infinity(), "n * G ≠ O !"
    print("  - n * G = O : ✓")
    
    # Vérifier quelques propriétés
    G2 = point_add(G, G)
    G2_alt = point_multiply(2, G)
    assert G2 == G2_alt, "2G calculé différemment donne des résultats différents !"
    print("  - G + G = 2 * G : ✓")
    
    print("Tous les paramètres sont valides !\n")
    return True


def demo():
    """
    Démonstration des opérations sur la courbe elliptique.
    """
    print("=" * 60)
    print("DÉMONSTRATION - Arithmétique sur courbe elliptique")
    print("=" * 60)
    print()
    
    # Afficher les paramètres
    print("Courbe : VSH (PlayStation 3)")
    print(f"Équation : y² = x³ + ax + b (mod p)")
    print(f"  p = 0x{P:040x}")
    print(f"  a = 0x{A:040x}")
    print(f"  b = 0x{B:040x}")
    print(f"  n = 0x{N:040x}")
    print()
    
    # Point générateur
    print(f"Point générateur G :")
    print(f"  Gx = 0x{GX:040x}")
    print(f"  Gy = 0x{GY:040x}")
    print()
    
    # Vérification
    verify_curve_params()
    
    # Exemples d'opérations
    print("-" * 60)
    print("Exemples d'opérations")
    print("-" * 60)
    
    # Addition
    print("\n1. Addition de points : 2G = G + G")
    G2 = point_add(G, G)
    print(f"   2G = {G2}")
    
    # Multiplication
    print("\n2. Multiplication scalaire : 10 * G")
    G10 = point_multiply(10, G)
    print(f"   10G = {G10}")
    
    # Vérification : 10G = 5G + 5G
    G5 = point_multiply(5, G)
    G5_plus_G5 = point_add(G5, G5)
    print(f"   Vérification : 5G + 5G = {G5_plus_G5}")
    print(f"   10G == 5G + 5G : {G10 == G5_plus_G5}")
    
    # Inverse
    print("\n3. Inverse d'un point : -G")
    neg_G = point_negate(G)
    print(f"   -G = {neg_G}")
    
    # G + (-G) = O
    O = point_add(G, neg_G)
    print(f"   G + (-G) = {O}")
    print(f"   Est le point à l'infini : {O.is_infinity()}")
    
    print()
    print("=" * 60)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    demo()
