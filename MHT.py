import hashlib
from typing import Any, List


class MHT:
    """
    A standard implementation of a Merkle Hash Tree
    """

    def __init__(self, data_list: List[Any]):
        """
        Initializes and builds the Merkle Hash Tree

        Args:
            data_list: A list of data elements to be included in the tree
        """
        self.data_list = data_list
        # Hash each individual data element to create the leaf nodes
        self.hashes = [self.get_hash(e) for e in data_list]
        self.hash_2_e = {h: e for h, e in zip(self.hashes, self.data_list)}
        # Store the layers of the tree during construction
        self.layers = []
        # A mapping from a hash to its index in the leaf layer
        self.hash_to_index = {}
        # The single root hash that represents the entire dataset
        self.root_hash = self.build_MHT()

    @staticmethod
    def get_hash(e):
        """
        Hashes a single data element using SHA-256
        """
        if isinstance(e, tuple):
            e_str = str(tuple(sorted(e))).encode('utf-8')
        else:
            e_str = str(e).encode('utf-8')
        return hashlib.sha256(e_str).digest()

    def build_MHT(self):
        """
        Constructs the Merkle Hash Tree from the bottom up
        """
        for i, h in enumerate(self.hashes):
            self.hash_to_index[h] = i
        current_layer = self.hashes
        self.layers.append(current_layer)
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                l_hash = current_layer[i]
                r_hash = current_layer[i + 1] if (i + 1 < len(current_layer)) else l_hash
                combined_hash = l_hash + r_hash
                parent_hash = hashlib.sha256(combined_hash).digest()
                next_layer.append(parent_hash)
            current_layer = next_layer
            self.layers.append(current_layer)
        return current_layer[0].hex()

    def get_proof(self, e):
        """
        Generates a Merkle proof for a given element
        """
        e_hash = self.get_hash(e)
        leaf_idx = self.hash_to_index.get(e_hash)
        if leaf_idx is None:
            raise ValueError("Element not found in the Merkle tree")
        hash_chain = []
        current_index = leaf_idx
        for layer in self.layers[:-1]:
            is_right = current_index % 2
            sibling_index = current_index - 1 if is_right else current_index + 1
            if sibling_index >= len(layer):
                sibling_hash = layer[current_index]
                position = "self"
            else:
                sibling_hash = layer[sibling_index]
                position = "left" if is_right else "right"
            hash_chain.append({"sibling_hash": sibling_hash.hex(), "position": position})
            current_index //= 2
        return {"element": e, "hash_chain": hash_chain, "root_hash": self.root_hash}

    @staticmethod
    def mht_recompute(proof):
        """
        Verifies a Merkle proof by recomputing the root hash
        """
        current_hash = MHT.get_hash(proof["element"])
        for step in proof["hash_chain"]:
            sibling_hash = bytes.fromhex(step["sibling_hash"])
            if step["position"] == "left":
                combined_hash = sibling_hash + current_hash
            elif step["position"] == "right":
                combined_hash = current_hash + sibling_hash
            else:
                combined_hash = current_hash + current_hash
            current_hash = hashlib.sha256(combined_hash).digest()
        return current_hash.hex()
