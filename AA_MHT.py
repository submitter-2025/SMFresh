import hashlib
from py_ecc.optimized_bn128 import curve_order
from typing import Any, List


class MHT:
    def __init__(self, items: List[Any]):
        self.items = items
        self.hashes = [self.get_hash(e) for e in items]
        self.hash_2_e = {hash: e for hash, e in zip(self.hashes, self.items)}
        self.hash_2_idx = {}
        self.layers = []
        self.merkle_root = self.build_tree()

    @staticmethod
    def get_hash(e):
        if isinstance(e, tuple):
            e_str = str(tuple(sorted(e))).encode('utf-8')
        else:
            e_str = str(e).encode('utf-8')

        return hashlib.sha256(e_str).digest()

    def build_tree(self):
        for idx, hash in enumerate(self.hashes):
            self.hash_2_idx[hash] = idx

        cur_layer = self.hashes
        self.layers.append(cur_layer)

        while len(cur_layer) > 1:
            next_layer = []
            for i in range(0, len(cur_layer), 2):
                l_hash = cur_layer[i]
                r_hash = cur_layer[i + 1] if (i + 1 < len(cur_layer)) else l_hash
                parent_hash = hashlib.sha256(l_hash + r_hash).digest()
                next_layer.append(parent_hash)

            cur_layer = next_layer
            self.layers.append(cur_layer)

        return cur_layer[0].hex()

    def get_proof(self, e):
        hash_chain = []
        cur_idx = self.hash_2_idx.get(self.get_hash(e))

        for layer in self.layers[:-1]:
            is_even = cur_idx % 2
            pair_idx = cur_idx - 1 if is_even else cur_idx + 1

            if pair_idx >= len(layer):
                pair_hash = layer[cur_idx]
                position = "self"
            else:
                pair_hash = layer[pair_idx]
                position = "left" if is_even else "right"

            hash_chain.append({"pair_hash": pair_hash.hex(), "position": position})
            cur_idx //= 2

        return {"e": e, "hash_chain": hash_chain, "merkle_root": self.merkle_root}

    @staticmethod
    def compute_root(proof):
        cur_hash = MHT.get_hash(proof["e"])

        for step in proof["hash_chain"]:
            pair_hash = bytes.fromhex(step["pair_hash"])

            if step["position"] == "left":
                merged_hash = pair_hash + cur_hash
            elif step["position"] == "right":
                merged_hash = cur_hash + pair_hash
            else:
                merged_hash = cur_hash + cur_hash

            cur_hash = hashlib.sha256(merged_hash).digest()

        return cur_hash.hex()

# ------------------------------------------------------------
# ------------------------------------------------------------

class AA_MHT:
    def __init__(self, items):
        self.items = items
        self.initial_tree = MHT(self.items)
        self.history = []
        self.merkle_root = hex(int(self.initial_tree.merkle_root, 16) % curve_order)[2:]

    def compute_root(self):
        initial_root = int(self.initial_tree.merkle_root, 16) % curve_order
        add_root = 0
        del_root = 0

        for op in self.history:
            tree = op['tree']
            tree_root = int(tree.merkle_root, 16) % curve_order

            if op['type'] == 'Add':
                add_root = (add_root + tree_root) % curve_order
            elif op['type'] == 'Del':
                del_root = (del_root + tree_root) % curve_order

        arith_root = (initial_root + add_root - del_root) % curve_order

        self.merkle_root = hex(arith_root)[2:]

    def addition(self, subtree):
        self.history.append({'type': 'Add',
                             'tree': MHT(subtree)})
        self.compute_root()

    def deletion(self, subtree):
        self.history.append({'type': 'Del',
                             'tree': MHT(subtree)})
        self.compute_root()

    @staticmethod
    def merge_hashes(hashes):
        hash_sum = 0

        for hash in hashes:
            hash_val = int(hash, 16) % curve_order
            hash_sum = (hash_sum + hash_val) % curve_order

        return hex(hash_sum)[2:]

    def get_proof(self, e):
        cur_hash = self.initial_tree.get_hash(e)
        subtree_proof = None

        for op in reversed(self.history):
            tree = op['tree']
            
            if cur_hash in tree.hash_2_idx:
                if op['type'] == 'Del':
                    raise ValueError(f"Element {e} has been deleted")
                elif op['type'] == 'Add':
                    subtree_proof = tree.get_proof(e)
                    break

        if subtree_proof is None:
            if cur_hash in self.initial_tree.hash_2_idx:
                subtree_proof = self.initial_tree.get_proof(e)
            else:
                raise ValueError(f"Element {e} not found in AA-MHT")

        add_root_hashes = [op['tree'].merkle_root for op in self.history if op['type'] == 'Add']
        del_root_hashes = [op['tree'].merkle_root for op in self.history if op['type'] == 'Del']

        add_merged_root = self.merge_hashes(add_root_hashes)
        del_merged_root = self.merge_hashes(del_root_hashes)

        init_root = hex(int(self.initial_tree.merkle_root, 16) % curve_order)[2:]

        proof = {"e": e,
                 "subtree_chain": subtree_proof["hash_chain"],
                 "subtree_root": subtree_proof["merkle_root"],
                 "initial_root": init_root,
                 "addition_root": add_merged_root,
                 "deletion_root": del_merged_root,
                 "merkle_root": self.merkle_root}

        return proof

    @staticmethod
    def compute_aa_root(proof):
        subtree_root = MHT.compute_root({"e": proof.get("e"),
                                         "hash_chain": proof.get("subtree_chain")})

        if subtree_root != proof.get("subtree_root"):
            if int(subtree_root, 16) != int(proof.get("subtree_root"), 16):
                raise ValueError("Subtree hash chain verification failed")

        initial_root = int(proof["initial_root"], 16)
        addition_root = int(proof["addition_root"], 16)
        deletion_root = int(proof["deletion_root"], 16)

        recomputed_aa_root = (initial_root + addition_root - deletion_root) % curve_order

        return hex(recomputed_aa_root)[2:]
    