import argparse
import sys
from Graph_Ops import gen_update
from Logic_Check import *
from multiprocessing.pool import ThreadPool


POOL = None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dataset', type=int, default=Config.GDB_IDX)
    parser.add_argument('--init_ratio', type=float, default=Config.INITIAL_RATIO, help="Initial Graph Ratio (<1.0 for stream)")
    parser.add_argument('--scale', type=int, default=None, help="Target Scale |V| (Overrides init_ratio if set)")
    parser.add_argument('--batch_size', type=int, default=Config.BATCH_SIZE)
    parser.add_argument('--ts_size', type=int, default=Config.TIMESTAMP_SIZE)
    parser.add_argument('--query', type=str, default=Config.SUB_IDX)
    parser.add_argument('--rounds', type=int, default=Config.N_ROUNDS)
    parser.add_argument('--interval', type=int, default=Config.QUERY_INTERVAL)
    args = parser.parse_args()

    Config.GDB_IDX = args.dataset
    Config.INITIAL_RATIO = args.init_ratio
    Config.BATCH_SIZE = args.batch_size
    Config.TIMESTAMP_SIZE = args.ts_size
    Config.SUB_IDX = args.query
    Config.N_ROUNDS = args.rounds
    Config.QUERY_INTERVAL = args.interval

    global POOL
    POOL = Pool(processes=96)

    # ------------------------------------------------------------
    # ------------------------------------------------------------

    (bls_sk, bls_pk), rsa_keys = init_key()

    g_nodes, g_edges, update_batches = Load_Graph(Config.GDB_IDX, Config.INITIAL_RATIO, Config.BATCH_SIZE, args.scale)
    print(f"[INFO] Graph Ready: |V|={len(g_nodes)}, |E|={len(g_edges)}")

    q_nodes, q_edges = get_subgraph(g_edges, Config.SUB_IDX)
    print(f"[INFO] Subgraph Ready: |V_q|={len(q_nodes)}, |E_q|={len(q_edges)}")

    q = q_nodes | q_edges
    rq = q.copy()

    init_ts, init_sig, cs_tree, (s_nodes, s_edges) = init_outsourcing(g_nodes, g_edges, bls_sk, Config.TIMESTAMP_SIZE)

    s = s_nodes | s_edges

    cf = get_cf(g_nodes, g_edges, s_nodes, s_edges,
                rsa_keys, Config.GDB_IDX, Config.INITIAL_RATIO, args.scale)

    # ------------------------------------------------------------
    # ------------------------------------------------------------

    Is_Integ, t_gen_proof, t_veri_proof, _ = verify_integrity([(rq, cs_tree)], init_sig, init_ts, bls_pk)

    Is_FreCo, t_blnd, t_sign, t_verify = TSFVP_PSICVP(q, s, rq, cf, rsa_keys)

    if not Is_Integ or not Is_FreCo:
        sys.exit(1)

    N, D = rsa_keys['N'], rsa_keys['D']

    for e in list(s) + list(rq):
        enc_val = pow(EllipticCurveUtils.data_2_scalar(e), D, N)
        cf.insert(enc_val)

    # ------------------------------------------------------------
    # ------------------------------------------------------------

    timer = Config.Timer()

    cur_sig = init_sig
    cur_ts = init_ts

    total_do = 0
    total_cs = 0

    for i in range(Config.N_ROUNDS):
        round_idx = i + 1

        update_type = "Addition"
        if update_batches and i < len(update_batches):
            batch_edges = update_batches[i]
            update_ts = datetime.now().strftime(f"%Y%m%d%H%M%S{round_idx}")
        else:
            if round_idx % 4 == 0:
                update_type = "Deletion"

            _, batch_edges, update_ts = gen_update(g_nodes, g_edges, Config.BATCH_SIZE, update_type,
                                                   locked_nodes=q_nodes, locked_edges=q_edges)

        batch_edges = {tuple(sorted(e)) for e in batch_edges}

        update_edges = batch_edges

        if update_type == "Addition":
            update_nodes = {node for edge in batch_edges for node in edge}
        else:
            edge_pool = g_edges - update_edges
            active_nodes = {node for edge in edge_pool for node in edge}
            updated_nodes = {node for edge in update_edges for node in edge}
            update_nodes = updated_nodes - active_nodes

        s_nodes, s_edges = mapping_function_psi(update_ts, Config.TIMESTAMP_SIZE)
        s = s_nodes | s_edges

        update_items = sorted(list(update_nodes) + list(update_edges), key=lambda x: str(x))
        s_items = sorted(list(s), key=lambda x: str(x))

        # ------------------------------------------------------------
        # ------------------------------------------------------------

        timer.tick()
        update_root = int(MHT(update_items).merkle_root, 16) % curve_order
        s_root = int(MHT(s_items).merkle_root, 16) % curve_order

        if update_type == "Addition":
            delta_root = (update_root + s_root) % curve_order
        else:
            delta_root = (-update_root + s_root) % curve_order

        delta_sigma = HomomorphicBLS.sign_update(bls_sk, cur_ts, update_ts, delta_root)
        t_do_update = timer.tock()

        # ------------------------------------------------------------
        # ------------------------------------------------------------

        timer.tick()
        cur_sig = HomomorphicBLS.aggregate(cur_sig, delta_sigma)

        if update_type == "Addition":
            cs_tree.addition(update_items)
            g_nodes |= update_nodes
            g_edges |= update_edges
        else:
            cs_tree.deletion(update_items)
            g_nodes -= update_nodes
            g_edges -= update_edges

        cs_tree.addition(s_items)

        # ------------------------------------------------------------
        # ------------------------------------------------------------

        raw_update = [EllipticCurveUtils.data_2_scalar(e) for e in update_items]
        raw_s = [EllipticCurveUtils.data_2_scalar(e) for e in s_items]

        args_update = [(x, D, N) for x in raw_update]
        args_s = [(x, D, N) for x in raw_s]

        enc_update = POOL.map(rsa_worker, args_update, chunksize=500)

        if len(args_s) > 500:
            enc_s = POOL.map(rsa_worker, args_s, chunksize=500)
        else:
            enc_s = [pow(x, D, N) for x in raw_s]

        to_insert = []
        if update_type == "Addition":
            to_insert.extend(enc_update)
        to_insert.extend(enc_s)

        with ThreadPool(processes=32) as tp:
            vals = tp.map(cf.ins, to_insert)

            for val in vals:
                cf.ert(val)

        if update_type != "Addition" and enc_update:
            cf.delete(enc_update)
        t_cs_update = timer.tock()

        # ------------------------------------------------------------
        # ------------------------------------------------------------

        cur_ts = update_ts

        total_do += t_do_update
        total_cs += t_cs_update

        if round_idx % Config.QUERY_INTERVAL == 0:
            q = q_nodes | q_edges
            rq = q.copy()

            Is_Integ, t_gen_proof, t_veri_proof, _ = verify_integrity([(rq, cs_tree)], cur_sig, cur_ts, bls_pk)

            Is_FreCo, t_blnd, t_sign, t_verify = TSFVP_PSICVP(q, s, rq, cf, rsa_keys)

            if not Is_Integ or not Is_FreCo:
                sys.exit(1)

            for e in list(s) + list(rq):
                enc_val = pow(EllipticCurveUtils.data_2_scalar(e), D, N)
                cf.insert(enc_val)

            tqdm.write(f"[RESULT] [ROUND {round_idx}] "
                       f"DO: {t_do_update:.0f}ms "
                       f"CS: {t_cs_update + (t_gen_proof + t_sign) * 1000:.0f}ms "
                       f"RP: {(t_veri_proof + t_blnd + t_verify) * 1000:.0f}ms")

            if Config.QUERY_INTERVAL == Config.N_ROUNDS:
                print(f"[RESULT] [TOTAL] DO: {total_do:.0f}ms CS: {total_cs:.0f}ms")

    print()


if __name__ == "__main__":
    main()
