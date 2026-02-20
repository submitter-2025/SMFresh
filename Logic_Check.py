import Config
import math
import secrets
import time
from AA_MHT import AA_MHT, MHT
from Crypto import CuckooFilter, EllipticCurveUtils, gen_rsa_keys, HomomorphicBLS
from datetime import datetime
from Graph_Ops import adjacency_list, gen_subgraph, load_graph, load_stream, mapping_function_psi, sample_graph
from multiprocessing import cpu_count, Pool
from py_ecc.optimized_bn128 import curve_order
from sympy import mod_inverse
from tqdm import tqdm


def Load_Graph(idx, init_ratio, batch_size, scale=None):
    file_path = Config.GDB_DIR + Config.GDB_NAMES[idx]

    if scale is not None:
        raw_nodes, raw_edges = load_graph(file_path)
        adj_list = adjacency_list(raw_nodes, raw_edges)

        fixed_nodes = set()
        fixed_edges = set()

        if Config.GDB_NAMES[idx] in Config.SUBGRAPHS and Config.SUB_IDX in Config.SUBGRAPHS[Config.GDB_NAMES[idx]]:

            instance = Config.SUBGRAPHS[Config.GDB_NAMES[idx]][Config.SUB_IDX][0]

            fixed_nodes = set(instance[0])
            fixed_edges = {tuple(sorted(e)) for e in instance[1]}

        nodes_set, edges_set = sample_graph(adj_list, scale, fixed_nodes, fixed_edges)

        update_batches = []

    elif init_ratio < 1.0:
        nodes_set, edges_set, update_batches = load_stream(file_path, init_ratio, batch_size)
    else:
        nodes_set, edges_set = load_graph(file_path)
        update_batches = []

    edges_set = {tuple(sorted(e)) for e in edges_set}

    return nodes_set, edges_set, update_batches


def get_subgraph(edges_set, key):
    subgraphs = Config.SUBGRAPHS.get(Config.GDB_NAMES[Config.GDB_IDX], {})

    if str(key) in subgraphs:
        instance = subgraphs[str(key)][0]
        return set(instance[0]), {tuple(sorted(e)) for e in instance[1]}

    try:
        res = gen_subgraph(edges_set, int(key))
        if res:
            return res[0], res[1]
    except ValueError:
        pass

    return set(), set()

# ------------------------------------------------------------
# ------------------------------------------------------------

def init_key():
    CM = Config.CacheManager()
    keys = CM.load(CM.key_path())

    if keys is None:
        bls_sk, bls_pk = HomomorphicBLS.gen_key()
        N, E, D = gen_rsa_keys()
        keys = {'N': N, 'E': E, 'D': D, 'BLS_SK': bls_sk, 'BLS_PK': bls_pk}
        CM.save(keys, CM.key_path())

    N, E, D = keys['N'], keys['E'], keys['D']
    bls_sk, bls_pk = keys.get('BLS_SK'), keys.get('BLS_PK')

    rsa_keys = {'N': N, 'E': E, 'D': D}

    return (bls_sk, bls_pk), rsa_keys


def init_outsourcing(g_nodes_set, g_edges_set, bls_sk, ts_size):
    init_ts = datetime.now().strftime("%Y%m%d%H%M%S%f")
    s_nodes_set, s_edges_set = mapping_function_psi(init_ts, ts_size)

    init_tree = MHT(sorted(list(g_nodes_set | g_edges_set | s_nodes_set | s_edges_set), key=lambda x: str(x)))
    init_root = int(init_tree.merkle_root, 16) % curve_order
    init_sig = HomomorphicBLS.sign_initial(bls_sk, init_ts, init_root)

    cs_tree = AA_MHT(sorted(list(g_nodes_set | g_edges_set | s_nodes_set | s_edges_set), key=lambda x: str(x)))

    return init_ts, init_sig, cs_tree, (s_nodes_set, s_edges_set)

# ------------------------------------------------------------
# ------------------------------------------------------------

def rsa_worker(args):
    val, D, N = args
    return pow(val, D, N)


def get_cf(g_nodes_set, g_edges_set, s_nodes_set, s_edges_set,
           rsa_keys, idx, init_ratio, scale=None):

    n_items = len(g_nodes_set) + len(g_edges_set) + len(s_nodes_set) + len(s_edges_set)
    capacity = math.ceil(n_items / 0.5)

    cf = CuckooFilter(capacity=capacity)
    N, D = rsa_keys['N'], rsa_keys['D']

    CM = Config.CacheManager()
    data_path = CM.data_path(idx, init_ratio, scale)
    GDB = CM.load(data_path)

    if GDB is None:
        task_G = [(EllipticCurveUtils.data_2_scalar(e), D, N) for e in list(g_nodes_set) + list(g_edges_set)]

        with Pool(cpu_count()) as p:
            GDB = list(tqdm(p.imap(rsa_worker, task_G)))
        CM.save(GDB, data_path)

    task_S = [(EllipticCurveUtils.data_2_scalar(e), D, N) for e in list(s_nodes_set) + list(s_edges_set)]

    enc_s = [pow(val, D, N) for val, _, _ in task_S]

    for val in GDB:
        cf.insert(val)

    for val in enc_s:
        cf.insert(val)

    return cf

# ------------------------------------------------------------
# ------------------------------------------------------------

def verify_integrity(vo, signature, ts, bls_pk):
    cs_gen_proof = 0
    rp_veri_proof = 0
    proofs = []

    for rq, cs_tree in vo:
        cur_proofs = []

        for e in rq:
            start_time = time.perf_counter()
            proof = cs_tree.get_proof(e)
            cs_gen_proof += time.perf_counter() - start_time

            cur_proofs.append(proof)

            Start_time = time.perf_counter()
            recomputed_root = cs_tree.compute_aa_root(proof)

            if recomputed_root != proof["merkle_root"]:
                return False, cs_gen_proof, rp_veri_proof, proofs
            rp_veri_proof += time.perf_counter() - Start_time

        proofs.append(cur_proofs)

        if rq:
            root = int(cur_proofs[0]["merkle_root"], 16)

            start_Time = time.perf_counter()
            is_valid = HomomorphicBLS.verify(bls_pk, ts, root, signature)
            rp_veri_proof += time.perf_counter() - start_Time

            if not is_valid:
                return False, cs_gen_proof, rp_veri_proof, proofs

    return True, cs_gen_proof, rp_veri_proof, proofs


def blinding(items, N, E):
    blinded = []
    r_invs = []

    for e in items:
        while True:
            r = secrets.randbelow(N - 2) + 2
            if math.gcd(r, N) == 1:
                break

        r_inv = mod_inverse(r, N)
        b = (EllipticCurveUtils.data_2_scalar(e) * pow(r, E, N)) % N

        blinded.append(b)
        r_invs.append(r_inv)

    return blinded, r_invs


def TSFVP_PSICVP(q, s, rq, cf, rsa_keys):
    N, E, D = rsa_keys['N'], rsa_keys['E'], rsa_keys['D']

    aug_rq = list(s) + list(rq)

    start_time = time.perf_counter()
    blinded, r_invs = blinding(aug_rq, N, E)
    rp_blind_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    resps = [pow(b, D, N) for b in blinded]
    cs_sign_time = time.perf_counter() - start_time

    start_time = time.perf_counter()

    unblinded = []
    for resp, r_inv in zip(resps, r_invs):
        unblinded.append((resp * r_inv) % N)

    verified = True

    for val in unblinded:
        if not cf.seek(val):
            verified = False
            break

    if verified:
        cf.delete(unblinded)

    rp_verify_time = time.perf_counter() - start_time

    if not verified:
        return False, rp_blind_time, cs_sign_time, rp_verify_time

    # ------------------------------------------------------------

    start_time = time.perf_counter()
    blinded, r_invs = blinding(list(q), N, E)
    rp_blind_time += (time.perf_counter() - start_time)

    start_time = time.perf_counter()
    resps = [pow(b, D, N) for b in blinded]
    cs_sign_time += (time.perf_counter() - start_time)

    start_time = time.perf_counter()
    unblinded = []
    for resp, r_inv in zip(resps, r_invs):
        unblinded.append((resp * r_inv) % N)

    fp_count = 0
    for val in unblinded:
        if cf.seek(val):
            fp_count += 1

    fp_rate = (2 * cf.bucket_size) / (2 ** cf.fp_size)
    fp_threshold = math.ceil(len(unblinded) * fp_rate * 3.0) + 3

    if fp_count > fp_threshold:
        verified = False

    rp_verify_time += (time.perf_counter() - start_time)

    return verified, rp_blind_time, cs_sign_time, rp_verify_time
