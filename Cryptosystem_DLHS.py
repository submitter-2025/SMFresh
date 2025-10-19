import hashlib
import secrets
from Crypto.Util.number import getPrime

# ---------- Public Parameters ----------
# Defines public parameters for the Discrete Logarithm-based Homomorphic Signature (DLHS) scheme

# A large prime number for the finite field Z_p
p = getPrime(128)
# A generator for the multiplicative group
g = 3

# ---------- Key Pair Generation ----------
# Generates a secret key (sk) and a public key (pk) for the Data Owner (DO)

# sk: a cryptographically secure random integer used as the private key
sk = secrets.randbelow(p - 2) + 1
# pk: the public key, computed as g^sk mod p
pk = pow(g, sk, p)


def normalize(e):
    """
    Normalizes a graph element (node or edge) into a canonical string representation
    Ensures that an edge (u, v) has the same representation as (v, u)

    Args:
        e: The graph element (an int for a node, a tuple for an edge)

    Returns:
        A unique string representation of the element
    """
    if isinstance(e, tuple) and len(e) == 2:
        return str(tuple(sorted(e)))
    return str(e)


def e_to_scalar(e):
    """
    Converts a graph element into a scalar (integer) via hashing
    This scalar is used as the message 'm' in the homomorphic signature scheme

    Args:
        e: The graph element (node or edge)

    Returns:
        An integer derived from the element's hash
    """
    norm_e = normalize(e)
    e_hash = int(hashlib.sha256(norm_e.encode()).hexdigest(), 16)
    return e_hash
