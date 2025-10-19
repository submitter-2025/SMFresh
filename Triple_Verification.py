import random
import sys
import time
from AA_MHT import AA_MHT
from Cryptosystem_DLHS import p, g, sk, pk, e_to_scalar
from Cryptosystem_RSA import N, E, D, CuckooFilter, Reinsertion
from datetime import datetime
from Execute_Verification import execute_integrity_verification, execute_psi_protocol, execute_correctness_verification
from functools import reduce
from gmpy2 import powmod
from Graph_Operation import (path_prefix, filename, subgraphs,
                             load_graph, load_temporal_stream, adjacency_list, sample_graph,
                             mapping_function_psi, generate_update, generate_subgraph)
from MHT import MHT
from Overhead_Monitor import *
from tqdm import tqdm


current_time = datetime.now().strftime("%Y%m%d%H%M%S%f")

count_dict = {("Addition", "Yes"): 0, ("Addition", "No"): 0,
              ("Deletion", "Yes"): 0, ("Deletion", "No"): 0}


def Triple_Verification():
    # --------------------------------
    GDB_INDEX = 0
    # g_nodes_set, g_edges_set, update_batches = load_temporal_stream(file_path=path_prefix + filename[GDB_INDEX], initial_ratio=0.1, batch_size=10000)
    SUB_INDEX = "3n3e"
    # sample_size = 2560 * 1000
    # --------------------------------
    num_s_edges = 20
    num_update_edges = 10000
    # num_subgraph_edges = 100
    # --------------------------------
    # batch_sizes = [5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000]
    # current_batch = batch_sizes[-4]
    # num_update_edges = current_batch
    # commit_interval = 1000000 // current_batch
    # --------------------------------
    load_factor = 0.1
    interval = 20
    # --------------------------------
    update_nodes_sigs, update_edges_sigs = [], []
    unioned_nodes_sigs, unioned_edges_sigs = [], []
    n_addition_buf, e_addition_buf = [], []
    n_deletion_buf, e_deletion_buf = [], []
    # --------------------------------
    current_iteration = 0
    max_iteration = 67
    # --------------------------------
    while current_iteration < max_iteration:
    # while current_iteration < commit_interval + 1:
        if current_iteration == 0:
            print("\n=================== 🥳INITIATING GRAPH DATA OUTSOURCING AND QUERY VERIFICATION🥳 ===================")
            DO_Init_TO, RP_Init_TO, CS_Init_TO = 0, 0, 0

            # The DO and RP generate a time-associated graph structure S through a mapping function
            Mapping_TO = time.perf_counter()
            s_nodes_set, s_edges_set = mapping_function_psi(current_time, num_s_edges)
            Mapping_TO = time.perf_counter() - Mapping_TO
            DO_Init_TO += Mapping_TO
            RP_Init_TO += Mapping_TO
            Record(Operation="Mapping", Time_Overhead=Mapping_TO, Update_Type=None, Query_or_Not="Yes")

            # The DO inserts the temporal structure S into the initial graph database G
            g_nodes_set, g_edges_set = load_graph(path_prefix + filename[GDB_INDEX])
            # adj_list = adjacency_list(g_nodes_set, g_edges_set)
            # g_nodes_set, g_edges_set = sample_graph(adj_list, sample_size, subgraphs[filename[GDB_INDEX]][SUB_INDEX][0], subgraphs[filename[GDB_INDEX]][SUB_INDEX][1])
            DO_Insert_S2G_TO = time.perf_counter()
            g_nodes_set |= s_nodes_set
            g_edges_set |= s_edges_set
            DO_Insert_S2G_TO = time.perf_counter() - DO_Insert_S2G_TO
            DO_Init_TO += DO_Insert_S2G_TO
            Record(Operation="DO_Insert_S2G", Time_Overhead=DO_Insert_S2G_TO, Update_Type=None, Query_or_Not="Yes")

            # The DO transforms the initial graph database G, which embeds the temporal structure S, into a Merkle tree and computes the root hash
            DO_TreeOp_TO = time.perf_counter()
            g_nodes_MHT = MHT(list(g_nodes_set))
            g_edges_MHT = MHT(list(g_edges_set))
            g_nodes_root = int(g_nodes_MHT.root_hash, 16)
            g_edges_root = int(g_edges_MHT.root_hash, 16)
            DO_TreeOp_TO = time.perf_counter() - DO_TreeOp_TO
            DO_Init_TO += DO_TreeOp_TO
            Record(Operation="DO_TreeOp", Time_Overhead=DO_TreeOp_TO, Update_Type=None, Query_or_Not="Yes")

            # The DO signs the root hash and sends it along with the data graph to the CS
            DO_SignRoot_TO = time.perf_counter()
            g_nodes_sig = pow(g, (sk * g_nodes_root) % (p - 1), p)
            g_edges_sig = pow(g, (sk * g_edges_root) % (p - 1), p)
            DO_SignRoot_TO = time.perf_counter() - DO_SignRoot_TO
            DO_Init_TO += DO_SignRoot_TO
            Record(Operation="DO_SignRoot", Time_Overhead=DO_SignRoot_TO, Update_Type=None, Query_or_Not="Yes")

            # Simulate a subgraph matching scenario to generate the ground-truth query result rq
            q_nodes_set, q_edges_set = subgraphs[filename[GDB_INDEX]][SUB_INDEX]
            # q_nodes_set, q_edges_set = generate_subgraph(g_nodes_set, g_edges_set, num_subgraph_edges)
            rq_nodes_set, rq_edges_set = q_nodes_set.copy(), q_edges_set.copy()

            # ————————————————————————————————— ✅️INTEGRITY VERIFICATION SUCCESSFUL✅ —————————————————————————————————
            # The CS initializes AA-MHTs for both the node and edge sets based on the initial graph database received from the DO
            CS_TreeOp_TO = time.perf_counter()
            node_AAMHT = AA_MHT(list(g_nodes_set))
            edge_AAMHT = AA_MHT(list(g_edges_set))
            CS_TreeOp_TO = time.perf_counter() - CS_TreeOp_TO
            CS_Init_TO += CS_TreeOp_TO
            Record(Operation="CS_TreeOp", Time_Overhead=CS_TreeOp_TO, Update_Type=None, Query_or_Not="Yes")

            is_integrity, CS_GenProof_TO, RP_VerifyProof_TO, proofs = execute_integrity_verification(VOs=[(rq_nodes_set, node_AAMHT), (rq_edges_set, edge_AAMHT)],
                                                                                                     expected_signatures={g_nodes_sig, g_edges_sig})
            if not is_integrity:
                sys.exit()

            CS_Init_TO += CS_GenProof_TO
            RP_Init_TO += RP_VerifyProof_TO
            Record(Operation="CS_GenProof", Time_Overhead=CS_GenProof_TO, Update_Type=None, Query_or_Not="Yes")
            Record(Operation="RP_VerifyProof", Time_Overhead=RP_VerifyProof_TO, Update_Type=None, Query_or_Not="Yes")

            print("\n============================ ❌INTEGRITY VERIFICATION FAILURE EXAMPLE❌ ============================")
            chosen_node = random.choice(list(rq_nodes_set))
            r9_nodes_set = {-e if e == chosen_node else e for e in rq_nodes_set}
            chosen_edge = random.choice(list(rq_edges_set))
            r9_edges_set = {(-x if (x, y) == chosen_edge else x, -y if (x, y) == chosen_edge else y) for (x, y) in rq_edges_set}
            for r9_set, AAMHT, g_sig in [(r9_nodes_set, node_AAMHT, g_nodes_sig),
                                         (r9_edges_set, edge_AAMHT, g_edges_sig)]:
                for e in r9_set:
                    proof = AAMHT.get_proof(e)
                    recomputed_root = AA_MHT.AA_recompute(proof)
                    if pow(pk, int(recomputed_root, 16), p) != g_sig:
                        print(f"😋Cause: \033[31m{chosen_node if r9_set == r9_nodes_set else chosen_edge}\033[0m was artificially \033[31mnegated\033[0m")

            # ————————————————————————————————— ✅️FRESHNESS VERIFICATION SUCCESSFUL✅ —————————————————————————————————
            # The RP merges the locally generated structure S with the received query result Rq to form the augmented result for subsequent verification
            RP_Insert_S2R_TO = time.perf_counter()
            rq_nodes_set |= s_nodes_set
            rq_edges_set |= s_edges_set
            RP_Insert_S2R_TO = time.perf_counter() - RP_Insert_S2R_TO
            RP_Init_TO += RP_Insert_S2R_TO
            Record(Operation="RP_Insert_S2R", Time_Overhead=RP_Insert_S2R_TO, Update_Type=None, Query_or_Not="Yes")

            # The CS encrypts the scalar representations of all elements in the data graph with its RSA private key
            CS_EncG_TO = time.perf_counter()
            print()
            enc_g_nodes = {powmod(e_to_scalar(node), D, N) for node in tqdm(g_nodes_set, desc=f"🫠Encrypting in progress...", unit=" elements")}
            enc_g_edges = {powmod(e_to_scalar(edge), D, N) for edge in tqdm(g_edges_set, desc=f"🫠Encrypting in progress...", unit=" elements")}
            CS_EncG_TO = time.perf_counter() - CS_EncG_TO
            CS_Init_TO += CS_EncG_TO
            Record(Operation="CS_EncG", Time_Overhead=CS_EncG_TO, Update_Type=None, Query_or_Not="Yes")

            # The CS inserts all encrypted elements into a newly initialized cuckoo filter and sends it to the RP
            CS_CF_TO = time.perf_counter()
            cf = CuckooFilter(capacity=int(len(enc_g_nodes | enc_g_edges) / load_factor / 4))
            for enc_data in enc_g_nodes | enc_g_edges:
                cf.insert(enc_data)
            CS_CF_TO = time.perf_counter() - CS_CF_TO
            CS_Init_TO += CS_CF_TO
            Record(Operation="CS_CF", Time_Overhead=CS_CF_TO, Update_Type=None, Query_or_Not="Yes")
            Reinsertion(cf, enc_g_nodes | enc_g_edges, verbose=True)

            is_fresh, RP_BlndRq_TO, CS_EncRq_TO, RP_SeekCF_TO, encrypted_rq_set, _ = execute_psi_protocol(sets=[rq_nodes_set, rq_edges_set], cf=cf,
                                                                                                          rsa_keys={'N': N, 'E': E, 'D': D}, should_exist=True)
            if not is_fresh:
                sys.exit()

            RP_Init_TO += RP_BlndRq_TO
            Record(Operation="RP_BlndRq", Time_Overhead=RP_BlndRq_TO, Update_Type=None, Query_or_Not="Yes")
            CS_Init_TO += CS_EncRq_TO
            Record(Operation="CS_EncRq", Time_Overhead=CS_EncRq_TO, Update_Type=None, Query_or_Not="Yes")

            print("============================ ❌FRESHNESS VERIFICATION FAILURE EXAMPLE❌ ============================")
            enc_9_nodes = enc_g_nodes - {powmod(e_to_scalar(node), D, N) for node in s_nodes_set}
            enc_9_edges = enc_g_edges - {powmod(e_to_scalar(edge), D, N) for edge in s_edges_set}
            df = CuckooFilter(capacity=int(len(enc_9_nodes | enc_9_edges) / 0.1 / 4))
            for enc_data in enc_9_nodes | enc_9_edges:
                df.insert(enc_data)
            Reinsertion(df, enc_9_nodes | enc_9_edges, verbose=False)
            enc_rq_nodes = {powmod(e_to_scalar(node), D, N) for node in (rq_nodes_set | s_nodes_set)}
            enc_rq_edges = {powmod(e_to_scalar(edge), D, N) for edge in (rq_edges_set | s_edges_set)}
            n_count, e_count = 0, 0
            for e in enc_rq_nodes:
                if not df.seek(e):
                    n_count += 1
            print(f"😭\033[31m{n_count}\033[0m nodes were not found in the Cuckoofilter, 😋caused by the incorrect version selection, and the length of s_nodes_set being \033[31m{len(s_nodes_set)}\033[0m")
            for e in enc_rq_edges:
                if not df.seek(e):
                    e_count += 1
            print(f"😭\033[31m{e_count}\033[0m edges were not found in the Cuckoofilter, 😋caused by the incorrect version selection, and the length of s_edges_set being \033[31m{len(s_edges_set)}\033[0m\n")

            # ———————————————————————————————— ✅️CORRECTNESS VERIFICATION SUCCESSFUL✅ ————————————————————————————————
            RP_Dif_TO, RP_BlndQ_TO, CS_EncQ_TO, _RP_SeekCF_TO, FP_Count = execute_correctness_verification(query_sets=[q_nodes_set, q_edges_set],
                                                                                                           encrypted_result_set=encrypted_rq_set,
                                                                                                           cf=cf, rsa_keys={'N': N, 'E': E, 'D': D})

            print("=========================== ❌CORRECTNESS VERIFICATION FAILURE EXAMPLE❌ ===========================")
            r9_nodes_set, r9_edges_set = rq_nodes_set.copy(), rq_edges_set.copy()
            altered_nodes_num = random.randint(1, len(r9_nodes_set - s_nodes_set))
            altered_edges_num = random.randint(1, len(r9_edges_set - s_edges_set))

            for r9_set, s_set, g_set, altered_num in [(r9_nodes_set, s_nodes_set, g_nodes_set, altered_nodes_num),
                                                      (r9_edges_set, s_edges_set, g_edges_set, altered_edges_num)]:
                if altered_num > 0:
                    e_to_remove = random.sample(list(r9_set - s_set), altered_num)
                    e_to_add = random.sample(list(g_set - r9_set), altered_num)
                    for e in e_to_remove:
                        r9_set.remove(e)
                    for e in e_to_add:
                        r9_set.add(e)

            enc_r9_nodes = {powmod(e_to_scalar(node), D, N) for node in r9_nodes_set}
            enc_r9_edges = {powmod(e_to_scalar(edge), D, N) for edge in r9_edges_set}

            ef = CuckooFilter(capacity=int(len(enc_g_nodes | enc_g_edges) / 0.1 / 4))
            for enc_data in enc_g_nodes | enc_g_edges:
                ef.insert(enc_data)
            Reinsertion(ef, enc_g_nodes | enc_g_edges, False)
            ef.delete(enc_r9_nodes | enc_r9_edges)

            enc_q_nodes = {powmod(e_to_scalar(node), D, N) for node in q_nodes_set}
            enc_q_edges = {powmod(e_to_scalar(edge), D, N) for edge in q_edges_set}

            n_count, e_count = 0, 0
            for e in enc_q_nodes:
                if ef.seek(e):
                    n_count += 1
            print(f"😭\033[31m{n_count}\033[0m nodes were found in the Cuckoofilter, 😋caused by \033[31m{altered_nodes_num}\033[0m nodes being deliberately altered in rq")

            for e in enc_q_edges:
                if ef.seek(e):
                    e_count += 1
            print(f"😭\033[31m{e_count}\033[0m edges were found in the Cuckoofilter, 😋caused by \033[31m{altered_edges_num}\033[0m edges being deliberately altered in rq\n")
            # --------------------------------
            RP_Init_TO += RP_Dif_TO
            Record(Operation="RP_Dif", Time_Overhead=RP_Dif_TO, Update_Type=None, Query_or_Not="Yes")
            RP_Init_TO += RP_BlndQ_TO
            Record(Operation="RP_BlndQ", Time_Overhead=RP_BlndQ_TO, Update_Type=None, Query_or_Not="Yes")
            CS_Init_TO += CS_EncQ_TO
            Record(Operation="CS_EncQ", Time_Overhead=CS_EncQ_TO, Update_Type=None, Query_or_Not="Yes")
            RP_SeekCF_TO += _RP_SeekCF_TO
            RP_Init_TO += _RP_SeekCF_TO
            Record(Operation="RP_SeekCF", Time_Overhead=RP_SeekCF_TO, Update_Type=None, Query_or_Not="Yes")

            Record(Operation="DO_Init", Time_Overhead=DO_Init_TO, Update_Type=None, Query_or_Not="Yes")
            Record(Operation="RP_Init", Time_Overhead=RP_Init_TO, Update_Type=None, Query_or_Not="Yes")
            Record(Operation="CS_Init", Time_Overhead=CS_Init_TO, Update_Type=None, Query_or_Not="Yes")

            num_rq_elements = len(rq_nodes_set | s_nodes_set) + len(rq_edges_set | s_edges_set)
            num_q_elements = len(q_nodes_set) + len(q_edges_set)

            cs_overhead = {"Signatures": get_size(g_nodes_sig) + get_size(g_edges_sig),
                           "Proofs": get_size(proofs),
                           "Filter": get_size(cf),
                           "Resp(rq)": num_rq_elements * (N.bit_length() + 7) // 8,
                           "Resp(q)": num_q_elements * (N.bit_length() + 7) // 8}
            rp_overhead = {"blind(rq)": num_rq_elements * (N.bit_length() + 7) // 8,
                           "blind(q)": num_q_elements * (N.bit_length() + 7) // 8}
            print_table(cs_overhead, rp_overhead)
            # --------------------------------
            current_iteration = 1
            print()
            print("——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————\n")

        else:
            if current_iteration == 1:
                print("======================== 🥳GRAPH DATA UPDATE AND VERIFICATION IN PROGRESS🥳 ========================\n")

            DO_Subseq_TO, RP_Subseq_TO, CS_Subseq_TO = 0, 0, 0

            update_type = "Deletion" if current_iteration % 2 == 0 else "Addition"
            # update_type = "Addition"
            query_or_not = "Yes" if current_iteration % 3 == 1 else "No"
            # query_or_not = "Yes" if current_iteration % commit_interval == 0 else "No"
            trigger = (current_iteration % interval == 0) or query_or_not == "Yes"
            # trigger = (current_iteration % commit_interval == 0)
            count_dict[(update_type, query_or_not)] += 1
            print(f"🥳The round {current_iteration} graph update ({update_type}) is currently in progress. RP’s query intention is: {query_or_not}")

            # The DO initiates a graph update request U at the specified update_time.
            update_nodes_set, update_edges_set, update_time = generate_update(g_nodes_set, g_edges_set, num_update_edges, update_type, protected_nodes=q_nodes_set, protected_edges=q_edges_set)
            # update_edges_set = set(list(update_batches[0])[(current_iteration-1)*current_batch : current_iteration*current_batch])
            # update_edges_set = update_batches[current_iteration-1]
            # update_nodes_set = {node for edge in update_edges_set for node in edge} - g_nodes_set
            update_time = datetime.now().strftime("%Y%m%d%H%M%S%f")

            # The DO and RP generate the time-associated graph structure S=(s_nodes_set, s_edges_set)
            DO_Mapping_TO = time.perf_counter()
            s_nodes_set, s_edges_set = mapping_function_psi(update_time, num_s_edges)
            DO_Mapping_TO = time.perf_counter() - DO_Mapping_TO
            DO_Subseq_TO += DO_Mapping_TO
            Record(Operation="DO_Mapping", Time_Overhead=DO_Mapping_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            if query_or_not == "Yes":
                RP_Mapping_TO = DO_Mapping_TO
                RP_Subseq_TO += RP_Mapping_TO
                Record(Operation="RP_Mapping", Time_Overhead=RP_Mapping_TO, Update_Type=update_type, Query_or_Not=query_or_not)

            # The DO inserts the structure S into the graph update U (only when update_type="append") to obtain the newly graph update structure U′=(unioned_nodes_set, unioned_edges_set)
            DO_Insert_S2U_TO = time.perf_counter()
            unioned_nodes_set = update_nodes_set | s_nodes_set if update_type == "Addition" else s_nodes_set
            unioned_edges_set = update_edges_set | s_edges_set if update_type == "Addition" else s_edges_set
            DO_Insert_S2U_TO = time.perf_counter() - DO_Insert_S2U_TO
            DO_Subseq_TO += DO_Insert_S2U_TO
            Record(Operation="DO_Insert_S2U", Time_Overhead=DO_Insert_S2U_TO, Update_Type=update_type, Query_or_Not=query_or_not)

            # After receiving the graph update, the CS generates the updated data graph G'=(updated_nodes_set, updated_edges_set)
            updated_edges_set = (g_edges_set | unioned_edges_set) - update_edges_set if update_type == "Deletion" else (g_edges_set | unioned_edges_set)
            updated_nodes_set = (g_nodes_set | unioned_nodes_set) - update_nodes_set if update_type == "Deletion" else (g_nodes_set | unioned_nodes_set)
            inter_1 = g_nodes_set & update_nodes_set if update_type == "Addition" else set()
            inter_2 = g_edges_set & update_edges_set if update_type == "Addition" else set()
            inter_3, inter_4 = update_nodes_set & s_nodes_set, update_edges_set & s_edges_set
            inter_5, inter_6 = s_nodes_set & g_nodes_set, s_edges_set & g_edges_set
            if any([inter_1, inter_2, inter_3, inter_4, inter_5, inter_6]):
                print(f"🤔Graph Data Conflict")

            # ————————————————————————————————— ✅️INTEGRITY VERIFICATION SUCCESSFUL✅ —————————————————————————————————

            # The DO builds separate Merkle trees for the node and edge sets of this update
            DO_TreeOp_TO = time.perf_counter()
            unioned_nodes_MHT = MHT(list(unioned_nodes_set))
            unioned_nodes_root = int(unioned_nodes_MHT.root_hash, 16)
            unioned_edges_MHT = MHT(list(unioned_edges_set))
            unioned_edges_root = int(unioned_edges_MHT.root_hash, 16)
            DO_TreeOp_TO = time.perf_counter() - DO_TreeOp_TO

            # The DO computes their root hashes for the subsequent homomorphic signature
            DO_SignRoot_TO = time.perf_counter()
            unioned_nodes_sig = pow(g, (sk * unioned_nodes_root) % (p - 1), p)
            unioned_edges_sig = pow(g, (sk * unioned_edges_root) % (p - 1), p)
            DO_SignRoot_TO = time.perf_counter() - DO_SignRoot_TO
            unioned_nodes_sigs.append(unioned_nodes_sig)
            unioned_edges_sigs.append(unioned_edges_sig)

            # The CS incorporates the update by adding the new sets of nodes and edges to their respective AA-MHTs
            CS_TreeOp_TO = time.perf_counter()
            node_AAMHT.addition(list(unioned_nodes_set))
            edge_AAMHT.addition(list(unioned_edges_set))
            CS_TreeOp_TO = time.perf_counter() - CS_TreeOp_TO

            if update_type == "Deletion":

                # For deletions, the DO also builds Merkle trees for the sets of elements being removed to compute their root hashes
                TreeOp_Start_Time = time.perf_counter()
                update_nodes_MHT = MHT(list(update_nodes_set))
                update_edges_MHT = MHT(list(update_edges_set))
                update_nodes_root = int(update_nodes_MHT.root_hash, 16)
                update_edges_root = int(update_edges_MHT.root_hash, 16)
                DO_TreeOp_TO += time.perf_counter() - TreeOp_Start_Time

                # The DO then signs the root hashes of the deleted sets; the RP will use the modular inverse of these signatures for verification
                SignRoot_Start_Time = time.perf_counter()
                update_nodes_RHsig = pow(g, (sk * update_nodes_root) % (p - 1), p)
                update_edges_RHsig = pow(g, (sk * update_edges_root) % (p - 1), p)
                DO_SignRoot_TO += time.perf_counter() - SignRoot_Start_Time
                update_nodes_sigs.append(update_nodes_RHsig)
                update_edges_sigs.append(update_edges_RHsig)

                # The CS updates its AA-MHTs by adding the Merkle trees of the deleted elements to its "Logical Deletion Tree"
                TreeOp_Start_Time = time.perf_counter()
                node_AAMHT.deletion(list(update_nodes_set))
                edge_AAMHT.deletion(list(update_edges_set))
                CS_TreeOp_TO += time.perf_counter() - TreeOp_Start_Time

            DO_Subseq_TO += DO_TreeOp_TO
            Record(Operation="DO_TreeOp", Time_Overhead=DO_TreeOp_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            DO_Subseq_TO += DO_SignRoot_TO
            Record(Operation="DO_SignRoot", Time_Overhead=DO_SignRoot_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            CS_Subseq_TO += CS_TreeOp_TO
            Record(Operation="CS_TreeOp", Time_Overhead=CS_TreeOp_TO, Update_Type=update_type, Query_or_Not=query_or_not)

            if query_or_not == "Yes":
                q_nodes_set, q_edges_set = subgraphs[filename[GDB_INDEX]][SUB_INDEX]
                # q_nodes_set, q_edges_set = generate_subgraph(updated_nodes_set, updated_edges_set, num_subgraph_edges)
                rq_nodes_set, rq_edges_set = q_nodes_set.copy(), q_edges_set.copy()

                # The RP homomorphically computes the expected signature by combining the previous state's signature
                # with all 'addition' signatures accumulated in this batch
                RP_GenHomo_TO = time.perf_counter()
                homo_nodes_sig = reduce(lambda acc, x: (acc * x) % p, unioned_nodes_sigs, g_nodes_sig)
                homo_edges_sig = reduce(lambda acc, x: (acc * x) % p, unioned_edges_sigs, g_edges_sig)
                RP_GenHomo_TO = time.perf_counter() - RP_GenHomo_TO

                # If there were any deletion operations in this batch, the RP continues the homomorphic calculation
                # by multiplying with the modular inverse of each 'deletion' signature
                if update_nodes_sigs or update_edges_sigs:
                    GenRHHomo_Start_Time = time.perf_counter()
                    homo_nodes_sig = reduce(lambda acc, x: (acc * pow(x, -1, p)) % p, update_nodes_sigs, homo_nodes_sig)
                    homo_edges_sig = reduce(lambda acc, x: (acc * pow(x, -1, p)) % p, update_edges_sigs, homo_edges_sig)
                    RP_GenHomo_TO += time.perf_counter() - GenRHHomo_Start_Time

                # Perform the integrity verification using the newly computed aggregate signature, which represents the expected current graph state
                is_integrity, CS_GenProof_TO, RP_VerifyProof_TO, _ = execute_integrity_verification(VOs=[(rq_nodes_set, node_AAMHT), (rq_edges_set, edge_AAMHT)],
                                                                                                         expected_signatures={homo_nodes_sig, homo_edges_sig})
                if not is_integrity:
                    sys.exit()

                RP_Subseq_TO += RP_GenHomo_TO
                Record(Operation="RP_GenHomo", Time_Overhead=RP_GenHomo_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                CS_Subseq_TO += CS_GenProof_TO
                Record(Operation="CS_GenProof", Time_Overhead=CS_GenProof_TO, Update_Type=update_type,Query_or_Not=query_or_not)
                RP_Subseq_TO += RP_VerifyProof_TO
                Record(Operation="RP_VerifyProof", Time_Overhead=RP_VerifyProof_TO, Update_Type=update_type,Query_or_Not=query_or_not)

                # After a successful verification, update the baseline signature to this new aggregate signature for the next round of updates
                g_nodes_sig, g_edges_sig = homo_nodes_sig, homo_edges_sig

                # Clear the signature caches for the processed batch to prepare for the next set of updates
                for cache in [update_nodes_sigs, update_edges_sigs, unioned_nodes_sigs, unioned_edges_sigs]:
                    cache.clear()

            # ————————————————————————————————— ✅️FRESHNESS VERIFICATION SUCCESSFUL✅ —————————————————————————————————

            # The CS encrypts the elements from the current update (both additions and deletions) using its private key
            # These encrypted sets are then staged in temporary buffers before being applied to the main encrypted graph dataset
            CS_EncNew_TO = time.perf_counter()
            enc_unioned_nodes = {powmod(e_to_scalar(node), D, N) for node in unioned_nodes_set}
            enc_unioned_edges = {powmod(e_to_scalar(edge), D, N) for edge in unioned_edges_set}
            n_addition_buf.append(enc_unioned_nodes)
            e_addition_buf.append(enc_unioned_edges)
            if update_type == "Deletion":
                enc_update_nodes = {powmod(e_to_scalar(node), D, N) for node in update_nodes_set}
                enc_update_edges = {powmod(e_to_scalar(edge), D, N) for edge in update_edges_set}
                n_deletion_buf.append(enc_update_nodes)
                e_deletion_buf.append(enc_update_edges)
            CS_EncNew_TO = time.perf_counter() - CS_EncNew_TO
            CS_Subseq_TO += CS_EncNew_TO
            Record(Operation="CS_EncNew", Time_Overhead=CS_EncNew_TO, Update_Type=update_type, Query_or_Not=query_or_not)

            # When triggered, the CS applies the entire batch of buffered updates to its master encrypted dataset
            # to create the new, up-to-date encrypted graph state for the next verification round
            if trigger:
                enc_updated_nodes = enc_g_nodes.copy()
                enc_updated_edges = enc_g_edges.copy()
                CS_UpdateCipher_TO = time.perf_counter()
                if n_addition_buf and e_addition_buf:
                    addition_nodes = set.union(*n_addition_buf)
                    addition_edges = set.union(*e_addition_buf)
                    enc_updated_nodes.update(addition_nodes)
                    enc_updated_edges.update(addition_edges)
                if n_deletion_buf and e_deletion_buf:
                    deletion_nodes = set.union(*n_deletion_buf)
                    deletion_edges = set.union(*e_deletion_buf)
                    enc_updated_nodes.difference_update(deletion_nodes)
                    enc_updated_edges.difference_update(deletion_edges)
                CS_UpdateCipher_TO = time.perf_counter() - CS_UpdateCipher_TO
                CS_Subseq_TO += CS_UpdateCipher_TO
                Record(Operation="CS_UpdateCipher", Time_Overhead=CS_UpdateCipher_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                enc_g_nodes, enc_g_edges = enc_updated_nodes, enc_updated_edges
                for cache in [n_addition_buf, e_addition_buf, n_deletion_buf, e_deletion_buf]:
                    cache.clear()

            if query_or_not == "Yes":
                CS_CF_TO = time.perf_counter()
                cf = CuckooFilter(capacity=int(len(enc_updated_nodes | enc_updated_edges) / load_factor / 4))
                for enc_data in enc_updated_nodes | enc_updated_edges:
                    cf.insert(enc_data)
                CS_CF_TO = time.perf_counter() - CS_CF_TO
                CS_Subseq_TO += CS_CF_TO
                Record(Operation="CS_CF", Time_Overhead=CS_CF_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                Reinsertion(cf, enc_updated_nodes | enc_updated_edges, False)

                RP_Insert_S2R_TO = time.perf_counter()
                rq_nodes_set |= s_nodes_set
                rq_edges_set |= s_edges_set
                RP_Insert_S2R_TO = time.perf_counter() - RP_Insert_S2R_TO
                RP_Subseq_TO += RP_Insert_S2R_TO
                Record(Operation="RP_Insert_S2R", Time_Overhead=RP_Insert_S2R_TO, Update_Type=update_type, Query_or_Not=query_or_not)

                is_fresh, RP_BlndRq_TO, CS_EncRq_TO, _RP_SeekCF_TO, encrypted_rq_set, _ = execute_psi_protocol(sets=[rq_nodes_set, rq_edges_set], cf=cf,
                                                                                                               rsa_keys={'N': N, 'E': E, 'D': D}, should_exist=True)
                if not is_fresh:
                    sys.exit()

                RP_Subseq_TO += RP_BlndRq_TO
                Record(Operation="RP_BlndRq", Time_Overhead=RP_BlndRq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                CS_Subseq_TO += CS_EncRq_TO
                Record(Operation="CS_EncRq", Time_Overhead=CS_EncRq_TO, Update_Type=update_type,Query_or_Not=query_or_not)
                RP_SeekCF_TO = _RP_SeekCF_TO

                # ———————————————————————————————— ✅️CORRECTNESS VERIFICATION SUCCESSFUL✅ ————————————————————————————————

            if query_or_not == "Yes":
                query_sets = [q_nodes_set, q_edges_set]
                RP_Dif_TO, RP_BlndQ_TO, CS_EncQ_TO, _RP_SeekCF_TO, FP_Count = execute_correctness_verification(query_sets=query_sets, encrypted_result_set=encrypted_rq_set,
                                                                                                               cf=cf, rsa_keys={'N': N, 'E': E, 'D': D})

                RP_Subseq_TO += RP_Dif_TO
                Record(Operation="RP_Dif", Time_Overhead=RP_Dif_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                RP_Subseq_TO += RP_BlndQ_TO
                Record(Operation="RP_BlndQ", Time_Overhead=RP_BlndQ_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                CS_Subseq_TO += CS_EncQ_TO
                Record(Operation="CS_EncQ", Time_Overhead=CS_EncQ_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                RP_SeekCF_TO += _RP_SeekCF_TO
                RP_Subseq_TO += _RP_SeekCF_TO
                Record(Operation="RP_SeekCF", Time_Overhead=RP_SeekCF_TO, Update_Type=update_type, Query_or_Not=query_or_not)

                Record(Operation="DO_Subseq", Time_Overhead=DO_Subseq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                Record(Operation="RP_Subseq", Time_Overhead=RP_Subseq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                Record(Operation="CS_Subseq", Time_Overhead=CS_Subseq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
            g_nodes_set, g_edges_set = updated_nodes_set, updated_edges_set
            current_iteration += 1
            if current_iteration == max_iteration:
            # if current_iteration == commit_interval + 1:
                print(f"🤔RP initiated queries for a total of \033[31m{count_dict[('Addition', 'Yes')]}\033[0m rounds of append-type graph updates, while \033[31m{count_dict[('Addition', 'No')]}\033[0m rounds of append-type graph updates were made without query initiation")
                print(f"🤔RP also initiated queries for \033[31m{count_dict[('Deletion', 'Yes')]}\033[0m rounds of remove-type graph updates, whereas \033[31m{count_dict[('Deletion', 'No')]}\033[0m rounds of remove-type graph updates were performed without initiating queries\n")
                print("——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————")
                Print()
            time.sleep(1)

if __name__ == "__main__":
    Triple_Verification()
