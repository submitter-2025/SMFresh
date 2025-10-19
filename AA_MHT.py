from MHT import MHT


class AA_MHT:
    """
    Implements the Arithmetic Aggregation Merkle Hash Tree as described in the SMFresh paper
    The root hash is computed homomorphically, allowing for efficient integrity verification of dynamic data using homomorphic signatures
    """

    def __init__(self, initial_list):
        """
        Initializes the AA_MHT with an initial dataset

        Args:
            initial_list: The initial list of data elements
        """
        self.initial_list = initial_list
        # The initial state is a standard Merkle Tree
        self.initial_tree = MHT(self.initial_list)
        # A history of subsequent addition and deletion operations
        self.history = []
        # The current root hash of the AA_MHT
        self.root_hash = self.initial_tree.root_hash

    def recompute_root_hash(self):
        """
        Recomputes the root hash based on the homomorphic property:
        Root = Initial_Root + Sum(Addition_Roots) - Sum(Deletion_Roots)
        """
        initial_root = int.from_bytes(bytes.fromhex(self.initial_tree.root_hash), 'big')
        addition_root = 0
        deletion_root = 0
        for op in self.history:
            tree = op['tree']
            tree_root = int.from_bytes(bytes.fromhex(tree.root_hash), 'big')
            if op['type'] == 'Addition':
                addition_root += tree_root
            elif op['type'] == 'Deletion':
                deletion_root += tree_root
        AA_root = hex(abs(initial_root + addition_root - deletion_root))[2:]
        if len(AA_root) % 2 != 0:
            AA_root = '0' + AA_root
        self.root_hash = AA_root

    def addition(self, s):
        """Processes an addition update by adding a new Merkle tree to the history"""
        self.history.append({'type': 'Addition', 'tree': MHT(s)})
        self.recompute_root_hash()

    def deletion(self, s):
        """Processes a deletion update by adding a new Merkle tree to the history"""
        self.history.append({'type': 'Deletion', 'tree': MHT(s)})
        self.recompute_root_hash()

    @staticmethod
    def merge_hashes(hashes):
        """A helper function to sum a list of hex-encoded hashes"""
        sum_hash = 0
        for h in hashes:
            h = int.from_bytes(bytes.fromhex(h), 'big')
            sum_hash += h
        sum_hash = hex(sum_hash)[2:]
        if len(sum_hash) % 2 != 0:
            sum_hash = '0' + sum_hash
        return sum_hash

    def get_proof(self, e):
        """
        Generates a comprehensive proof for an element's membership
        The proof includes the standard Merkle path and all components needed to recompute the final AA_MHT root hash
        """
        e_hash = self.initial_tree.get_hash(e)
        sub_proof = None
        for op in reversed(self.history):
            tree = op['tree']
            if e_hash in tree.hash_to_index:
                if op['type'] == 'Deletion':
                    raise ValueError("Element exists in history but was removed")
                elif op['type'] == 'Addition':
                    sub_proof = tree.get_proof(e)
                    break
        if sub_proof is None:
            if e_hash in self.initial_tree.hash_to_index:
                sub_proof = self.initial_tree.get_proof(e)
            else:
                print(f"😭Error: Element \033[31m{e}\033[0m does not exist in the graph.")
                return None
        addition_root_hashes = [op['tree'].root_hash for op in self.history if op['type'] == 'Addition']
        deletion_root_hashes = [op['tree'].root_hash for op in self.history if op['type'] == 'Deletion']
        merged_addition_root = self.merge_hashes(addition_root_hashes)
        merged_deletion_root = self.merge_hashes(deletion_root_hashes)
        AA_proof = {"element": e,
                    "sub_hash_chain": sub_proof["hash_chain"],
                    "sub_root": sub_proof["root_hash"],
                    "initial_root": self.initial_tree.root_hash,
                    "addition_root": merged_addition_root,
                    "deletion_root": merged_deletion_root,
                    "Root_Hash": self.root_hash if self.root_hash else "0"}
        return AA_proof

    @staticmethod
    def AA_recompute(AA_proof):
        """
        Verifies an AA_MHT proof by recomputing the final root hash
        """
        if not isinstance(AA_proof, dict):
            print(f"😭Error: The provided proof is not a dictionary. Instead, it's of type {type(AA_proof)}")
            return "FA15E"
        e = AA_proof.get("element")
        sub_hash_chain = AA_proof.get("sub_hash_chain")
        claimed_sub_root = AA_proof.get("sub_root")
        minor_proof = {"element": e, "hash_chain": sub_hash_chain}
        recomputed_sub_root = MHT.mht_recompute(minor_proof)
        if recomputed_sub_root != claimed_sub_root:
            raise ValueError("Sub-proof verification failed")
        try:
            initial_root = AA_proof["initial_root"]
            addition_root = AA_proof["addition_root"]
            deletion_root = AA_proof["deletion_root"]
            initial_root_val = int.from_bytes(bytes.fromhex(initial_root), 'big') if initial_root else 0
            addition_root_val = int.from_bytes(bytes.fromhex(addition_root), 'big') if addition_root else 0
            deletion_root_val = int.from_bytes(bytes.fromhex(deletion_root), 'big') if deletion_root else 0
            Recomputed_Root_Hash = abs(initial_root_val + addition_root_val - deletion_root_val)
            Recomputed_Root_Hash = hex(Recomputed_Root_Hash)[2:]
            if len(Recomputed_Root_Hash) % 2 != 0:
                Recomputed_Root_Hash = '0' + Recomputed_Root_Hash
            return Recomputed_Root_Hash
        except (KeyError, ValueError) as e:
            raise ValueError(f"Failed to compute final arithmetic root: {e}")
