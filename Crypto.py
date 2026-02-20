import hashlib
import numpy as np
import random
import secrets
from py_ecc.optimized_bn128 import add, curve_order, G1, G2, multiply, neg, pairing
from sympy import mod_inverse, randprime


class EllipticCurveUtils:
    BASE_POINT = multiply(G1, 5201314)

    @staticmethod
    def data_2_scalar(data):
        if isinstance(data, int):
            data_bytes = str(data).encode()
        elif isinstance(data, str):
            data_bytes = data.encode()
        elif isinstance(data, bytes):
            data_bytes = data
        else:
            data_bytes = str(data).encode()

        return int.from_bytes(hashlib.sha256(data_bytes).digest(), 'big') % curve_order

    @staticmethod
    def ts_2_point(ts):
        scalar = EllipticCurveUtils.data_2_scalar(ts)
        return multiply(G1, scalar)


class HomomorphicBLS:
    @staticmethod
    def gen_key():
        sk = secrets.randbelow(curve_order - 1) + 1
        pk = multiply(G2, sk)
        return sk, pk

    @staticmethod
    def sign_initial(sk, ts, root):
        p_ts = EllipticCurveUtils.ts_2_point(ts)

        p_root = multiply(EllipticCurveUtils.BASE_POINT, root % curve_order)

        p_msg = add(p_ts, p_root)

        return multiply(p_msg, sk)

    @staticmethod
    def sign_update(sk, _ts, ts_, root):
        p__ts = EllipticCurveUtils.ts_2_point(_ts)
        p_ts_ = EllipticCurveUtils.ts_2_point(ts_)
        p_ts = add(p_ts_, neg(p__ts))

        p_root = multiply(EllipticCurveUtils.BASE_POINT, root % curve_order)

        p_msg = add(p_ts, p_root)

        return multiply(p_msg, sk)

    @staticmethod
    def aggregate(_sigma, sigma_):
        return add(_sigma, sigma_)

    @staticmethod
    def verify(pk, ts, root, signature):
        p_ts = EllipticCurveUtils.ts_2_point(ts)

        p_root = multiply(EllipticCurveUtils.BASE_POINT, root % curve_order)

        p_msg = add(p_ts, p_root)

        lhs = pairing(G2, signature)
        rhs = pairing(pk, p_msg)

        return lhs == rhs

# ------------------------------------------------------------
# ------------------------------------------------------------

def gen_rsa_keys(bits=512, e=65537):
    p = randprime(2 ** (bits // 2 - 1), 2 ** bits // 2)
    q = randprime(2 ** (bits // 2 - 1), 2 ** bits // 2)

    while p == q:
        q = randprime(2 ** (bits // 2 - 1), 2 ** bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    d = mod_inverse(e, phi)

    return n, e, d


class CuckooFilter:
    def __init__(self, capacity, bucket_size=4, max_kicks=100):
        self.n_buckets = capacity
        self.bucket_size = bucket_size
        self.max_kicks = max_kicks
        self.fp_size = 12
        self.fp_mask = (1 << self.fp_size) - 1
        self.buckets = np.zeros((self.n_buckets, self.bucket_size), dtype=np.uint16)
        self.n_items = 0

    @staticmethod
    def to_int_hash(data, salt=b''):
        hasher = hashlib.sha256()
        hasher.update(salt)

        if isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, int):
            data = data.to_bytes(max(1, (data.bit_length() + 7) // 8), 'big')

        hasher.update(data)

        digest = hasher.digest()

        return int.from_bytes(digest[:8], byteorder='big', signed=False)

    def get_fp_and_indices(self, e):
        if hasattr(e, 'to_bytes'):
            e_bytes = e.to_bytes((e.bit_length() + 7) // 8, 'big')
        else:
            e_bytes = str(e).encode('utf-8')

        fp_val = self.to_int_hash(e_bytes, salt=b"fp_salt_")
        fp = fp_val & self.fp_mask

        fp = fp if fp != 0 else 1

        idx1 = self.to_int_hash(e_bytes, salt=b"idx1_salt_") % self.n_buckets

        fp_bytes = int(fp).to_bytes((self.fp_size + 7) // 8, 'big')
        fp_hash = self.to_int_hash(fp_bytes, salt=b"idx2_salt_")
        idx2 = (idx1 ^ fp_hash) % self.n_buckets

        return fp, idx1, idx2

    def get_alter_idx(self, idx, fp):
        fp_bytes = int(fp).to_bytes((self.fp_size + 7) // 8, 'big')
        fp_hash = self.to_int_hash(fp_bytes, salt=b"idx2_salt_")

        return (idx ^ fp_hash) % self.n_buckets

    def ins(self, e):
        fp, idx1, idx2 = self.get_fp_and_indices(e)
        return fp, idx1, idx2

    def ert(self, vals):
        fp, idx1, idx2 = vals

        free_slot1 = np.where(self.buckets[idx1] == 0)[0]
        if len(free_slot1) > 0:
            self.buckets[idx1, free_slot1[0]] = fp
            self.n_items += 1
            return True

        free_slot2 = np.where(self.buckets[idx2] == 0)[0]
        if len(free_slot2) > 0:
            self.buckets[idx2, free_slot2[0]] = fp
            self.n_items += 1
            return True

        f = fp
        bucket_idx = random.choice([idx1, idx2])

        for _ in range(self.max_kicks):
            kicked_slot = secrets.choice(range(self.bucket_size))
            f, self.buckets[bucket_idx, kicked_slot] = self.buckets[bucket_idx, kicked_slot], f
            bucket_idx = self.get_alter_idx(bucket_idx, f)

            free_slots = np.where(self.buckets[bucket_idx] == 0)[0]
            if len(free_slots) > 0:
                self.buckets[bucket_idx, free_slots[0]] = f
                self.n_items += 1
                return True

        return False

    def insert(self, e):
        fp, idx1, idx2 = self.get_fp_and_indices(e)

        if np.any(self.buckets[idx1] == 0):
            free_slot = np.where(self.buckets[idx1] == 0)[0][0]
            self.buckets[idx1, free_slot] = fp
            self.n_items += 1
            return True

        if np.any(self.buckets[idx2] == 0):
            free_slot = np.where(self.buckets[idx2] == 0)[0][0]
            self.buckets[idx2, free_slot] = fp
            self.n_items += 1
            return True

        f = fp
        bucket_idx = random.choice([idx1, idx2])

        for _ in range(self.max_kicks):
            kicked_slot = secrets.choice(range(self.bucket_size))
            f, self.buckets[bucket_idx, kicked_slot] = self.buckets[bucket_idx, kicked_slot], f
            bucket_idx = self.get_alter_idx(bucket_idx, f)

            if np.any(self.buckets[bucket_idx] == 0):
                free_slot = np.where(self.buckets[bucket_idx] == 0)[0][0]
                self.buckets[bucket_idx, free_slot] = f
                self.n_items += 1
                return True

        return False

    def delete(self, items):
        count = 0

        for e in items:
            fp, idx1, idx2 = self.get_fp_and_indices(e)

            for i in range(self.bucket_size):
                if self.buckets[idx1, i] == fp:
                    self.buckets[idx1, i] = 0
                    self.n_items -= 1
                    count += 1

            for i in range(self.bucket_size):
                if self.buckets[idx2, i] == fp:
                    self.buckets[idx2, i] = 0
                    self.n_items -= 1
                    count += 1

        return count

    def seek(self, e):
        fp, idx1, idx2 = self.get_fp_and_indices(e)

        if np.any(self.buckets[idx1] == fp) or np.any(self.buckets[idx2] == fp):
            return True

        return False
