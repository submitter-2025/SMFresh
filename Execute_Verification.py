import math
import secrets
import sys
import time
from AA_MHT import AA_MHT
from Cryptosystem_DLHS import p, pk, e_to_scalar
from sympy import mod_inverse


def execute_integrity_verification(VOs, expected_signatures):
    """
    Executes the integrity verification protocol for a given set of results

    Args:
        VOs (list): A list of tuples, where each tuple is (result_set, AAMHT_instance)
                    Example: [(rq_nodes_set, node_AAMHT), (rq_edges_set, edge_AAMHT)]
        expected_signatures (set): A set containing the expected final DLHS signatures
                                   Example: {g_nodes_sig, g_edges_sig}

    Returns:
        tuple: A tuple containing:
               - is_verified (bool): True if verification succeeds, False otherwise
               - CS_GenProof_TO (float): Time spent by CS generating proofs
               - RP_VerifyProof_TO (float): Time spent by RP verifying proofs
               - proofs (list): The list of generated proof objects
    """
    CS_GenProof_TO, RP_VerifyProof_TO = 0, 0
    recomputed_roots, proofs = set(), []

    for result_set, AAMHT in VOs:
        for e in result_set:

            # CS generates the AA_MHT membership proof
            start_time = time.perf_counter()
            proof = AAMHT.get_proof(e)
            CS_GenProof_TO += time.perf_counter() - start_time

            # RP verifies the proof by recomputing the root hash
            start_time = time.perf_counter()
            recomputed_root = AA_MHT.AA_recompute(proof)
            if recomputed_root != proof["Root_Hash"]:
                sys.exit()
            RP_VerifyProof_TO += time.perf_counter() - start_time

            recomputed_roots.add(recomputed_root)
            proofs.append(proof)

    # RP checks for consistency: exactly one unique root hash per data set (nodes and edges)
    if len(recomputed_roots) != len(VOs):
        sys.exit()

    # RP verifies the homomorphic signatures against the recomputed roots
    start_time = time.perf_counter()
    derived_sigs = {pow(pk, int(hex_str, 16), p) for hex_str in recomputed_roots}
    if derived_sigs != expected_signatures:
        print(f"😭Error: Integrity verification failed")
        return False, CS_GenProof_TO, RP_VerifyProof_TO, proofs
    RP_VerifyProof_TO += time.perf_counter() - start_time

    return True, CS_GenProof_TO, RP_VerifyProof_TO, proofs


def blinding(sets, N, E):
    """
    Blinds sets of elements for the RSA-PSI protocol

    Args:
        sets (list): A list of sets to be blinded (e.g., [nodes_set, edges_set])
        N (int): The RSA modulus
        E (int): The RSA public exponent

    Returns:
        tuple: A tuple containing:
               - blinded (list): A flat list of all blinded elements
               - inverses (list): A flat list of corresponding inverse factors for unblinding
    """
    blinded, inverses = [], []

    for s in sets:
        for e in s:
            # Find a random factor 'r' that is coprime to N
            while True:
                r = secrets.randbelow(N - 2) + 2
                if math.gcd(r, N) == 1:
                    break
            r_inv = mod_inverse(r, N)

            # Blind the element: (e * r^E) mod N
            blnd_e = (e_to_scalar(e) * pow(r, E, N)) % N
            blinded.append(blnd_e)
            inverses.append(r_inv)

    return blinded, inverses


def execute_psi_protocol(sets, cf, rsa_keys, should_exist=True):
    """
    Executes the full RSA-PSI challenge-response protocol and verification

    Args:
        sets (list): A list of element sets to be challenged (e.g., [nodes_set, edges_set])
        cf (CuckooFilter): The Cuckoo Filter instance to check against
        rsa_keys (dict): A dictionary containing RSA keys: {'N': N, 'E': E, 'D': D}
        should_exist (bool): Specifies the verification logic
                             - True: Expects elements to be in the filter (for freshness)
                             - False: Expects elements NOT to be in the filter (for correctness)

    Returns:
        tuple: A tuple containing:
               - is_verified (bool): The overall verification result
               - rp_blind_time (float): Time for RP's blinding step
               - cs_encrypt_time (float): Time for CS's encryption step
               - rp_seek_time (float): Time for RP's unblinding and filter seeking step (corresponds to RP_SeekCF_TO)
               - encrypted_elements (set): The resulting set of unblinded, encrypted elements
               - false_positive_count (int): The number of elements found when they should not exist
    """
    N, E, D = rsa_keys['N'], rsa_keys['E'], rsa_keys['D']

    # RP blinds the elements and creates the challenge
    start_time = time.perf_counter()
    blinded_elements, inverse_factors = blinding(sets, N, E)
    rp_blind_time = time.perf_counter() - start_time

    # The CS computes the response to each blinded challenge from the RP
    start_time = time.perf_counter()
    cs_responses = [pow(b, D, N) for b in blinded_elements]
    cs_encrypt_time = time.perf_counter() - start_time

    # RP receives the response, unblinds it, and checks the filter
    start_time = time.perf_counter()
    encrypted_elements = set()
    verification_passed = True
    fp_count = 0

    for response, r_inv in zip(cs_responses, inverse_factors):
        unblinded_e = (response * r_inv) % N
        encrypted_elements.add(unblinded_e)

        found = cf.seek(unblinded_e)
        if should_exist and not found:
            print("😭Error: Freshness verification failed. Element not found in filter")
            verification_passed = False
            break
        if not should_exist and found:
            # This indicates a potential failure or a false positive
            print("🤔Potential correctness failure or false positive: Element found in diff set")
            fp_count += 1

    rp_seek_time = time.perf_counter() - start_time

    return verification_passed, rp_blind_time, cs_encrypt_time, rp_seek_time, encrypted_elements, fp_count


def execute_correctness_verification(query_sets, encrypted_result_set, cf, rsa_keys):
    """
    Executes the full correctness verification protocol (PSICVP)

    Args:
        query_sets (list): A list of the query graph's element sets [q_nodes, q_edges]
        encrypted_result_set (set): The set of encrypted elements from the augmented result (Rq U S)
        cf (CuckooFilter): The Cuckoo Filter instance
        rsa_keys (dict): A dictionary containing RSA keys

    Returns:
        tuple: A tuple containing all the detailed timing metrics for recording.
    """
    # RP removes the result set from the filter to create the difference set G - Rq
    start_time = time.perf_counter()
    cf.delete(encrypted_result_set)
    rp_dif_time = time.perf_counter() - start_time

    # Execute the PSI protocol against the modified filter
    _, rp_blind_time, cs_encrypt_time, rp_seek_time, _, fp_count = execute_psi_protocol(sets=query_sets, cf=cf,
                                                                                        rsa_keys=rsa_keys, should_exist=False)

    # Check if the observed false positive count is within the acceptable threshold
    num_queries = sum(len(s) for s in query_sets)
    FP_Rate = (2 * cf.bucket_size) / (2 ** cf.fp_size)
    FP_Threshold = math.ceil(num_queries * FP_Rate * 2)

    if fp_count > FP_Threshold:
        print("😭Error: The number of observed false positives significantly exceeds the theoretical rate")
        sys.exit()

    return rp_dif_time, rp_blind_time, cs_encrypt_time, rp_seek_time, fp_count
