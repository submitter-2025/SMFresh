import collections
import hashlib
import os
import random
from datetime import datetime


def load_graph(file_path):
    nodes_set, edges_set = set(), set()

    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            lines = file.readlines()

        for line in lines:
            if not line.startswith('#'):
                parts = line.split()

                if len(parts) >= 2:
                    u, v = int(parts[0]), int(parts[1])
                    nodes_set.add(u)
                    nodes_set.add(v)
                    edges_set.add(tuple(sorted((u, v))))

    return nodes_set, edges_set


def adjacency_list(nodes, edges):
    adj_list = collections.defaultdict(set)

    for u, v in edges:
        adj_list[u].add(v)
        adj_list[v].add(u)

    for node in nodes:
        if node not in adj_list:
            adj_list[node] = set()

    return adj_list

# ------------------------------------------------------------
# ------------------------------------------------------------

def load_stream(file_path, initial_ratio, batch_size):
    ts_edges = []
    line_idx = 0

    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            for line in file:
                if line.startswith('#') or line.startswith('%'):
                    continue
                parts = line.split()
                try:
                    if len(parts) >= 3:
                        u, v, ts = int(parts[0]), int(parts[1]), int(parts[2])
                    elif len(parts) == 2:
                        u, v = int(parts[0]), int(parts[1])
                        ts = line_idx
                    else:
                        continue

                    if u != v:
                        ts_edges.append((ts, tuple(sorted((u, v)))))

                    line_idx += 1
                except ValueError:
                    continue
    else:
        return set(), set(), []

    edge_2_ts = {}
    for ts, edge in ts_edges:
        if edge not in edge_2_ts:
            edge_2_ts[edge] = ts
        else:
            edge_2_ts[edge] = min(edge_2_ts[edge], ts)

    sorted_edges = sorted([(ts, edge) for edge, ts in edge_2_ts.items()])
    sorted_edges = [edge for ts, edge in sorted_edges]
    n_edges = len(sorted_edges)

    init_size = int(n_edges * initial_ratio)
    if init_size == 0 and n_edges > 0:
        init_size = min(100, n_edges)

    edges_set = set(sorted_edges[:init_size])
    nodes_set = {node for edge in edges_set for node in edge}
    stream_edges = sorted_edges[init_size:]

    update_batches = []
    for i in range(0, len(stream_edges), batch_size):
        batch = stream_edges[i:i + batch_size]
        if batch:
            update_batches.append(set(batch))

    return nodes_set, edges_set, update_batches


def sample_graph(adj_list, n_samples, locked_nodes, locked_edges):
    fixed_nodes = locked_nodes.copy()

    for u, v in locked_edges:
        fixed_nodes.add(u)
        fixed_nodes.add(v)

    sampled_nodes = fixed_nodes.copy()
    node_sequence = list(fixed_nodes)

    node_pool = list(adj_list.keys())
    if not node_sequence:
        if not node_pool:
            return set(), set()

        start_node = random.choice(node_pool)
        sampled_nodes.add(start_node)
        node_sequence.append(start_node)

    cur_node = node_sequence[-1]

    while len(sampled_nodes) < n_samples:
        adjacent_nodes = adj_list.get(cur_node, set())

        pending_nodes = [n for n in adjacent_nodes if n not in sampled_nodes]

        if pending_nodes:
            next_node = random.choice(pending_nodes)
            sampled_nodes.add(next_node)
            node_sequence.append(next_node)
            cur_node = next_node
        else:
            cur_node = random.choice(node_sequence)

            if len(sampled_nodes) >= len(node_pool):
                break

    sampled_edges = locked_edges.copy()

    for u in sampled_nodes:
        adjacent_nodes = adj_list.get(u, set())
        for v in adjacent_nodes:
            if v in sampled_nodes and u < v:
                sampled_edges.add(tuple(sorted((u, v))))

    return sampled_nodes, sampled_edges

# ------------------------------------------------------------
# ------------------------------------------------------------

def gen_update(nodes_set, edges_set, n_update_edges, update_type,
               locked_nodes=None, locked_edges=None):
    update_time = datetime.now().strftime("%Y%m%d%H%M%S%f")

    if update_type == "Addition":
        nodes_2_add, edges_2_add = set(), set()

        max_node = max(nodes_set)
        active_nodes = list(nodes_set)

        new_node = max_node + 1

        for _ in range(n_update_edges):
            nodes_2_add.add(new_node)

            if active_nodes:
                active_node = random.choice(active_nodes)
                edges_2_add.add(tuple(sorted((new_node, active_node))))
            new_node += 1

        return nodes_2_add, edges_2_add, update_time

    elif update_type == "Deletion":
        if not locked_nodes:
            locked_nodes = set()
        if not locked_edges:
            locked_edges = set()

        valid_edges = {edge for edge in edges_set if edge[0] not in locked_nodes and
                                                     edge[1] not in locked_nodes and
                                                     edge not in locked_edges}

        if not valid_edges:
            return set(), set(), update_time

        edges_2_del = set(random.sample(list(valid_edges), k=min(len(valid_edges), n_update_edges)))
        return set(), edges_2_del, update_time

    return set(), set(), update_time


def mapping_function_psi(ts, n_edges):
    edges_set = set()
    from_nodes = set()
    to_nodes = set()

    seed = int.from_bytes(hashlib.sha256(str(ts).encode('utf-8')).digest()[:8], 'big')
    rng = random.Random(seed)

    base_id = seed % 1000000 + 10000

    for i in range(n_edges):
        r1 = rng.randint(1, 10000)
        r2 = rng.randint(1, 10000)

        from_node = -(base_id + r1 + i)
        to_node = -(base_id + r2 + i + 100000)

        from_nodes.add(from_node)
        to_nodes.add(to_node)

    nodes_set = from_nodes | to_nodes

    from_nodes = sorted(list(from_nodes))
    to_nodes = sorted(list(to_nodes))

    rng.shuffle(from_nodes)
    rng.shuffle(to_nodes)

    count = 0
    idx_from = 0
    idx_to = 0

    while count < n_edges:
        u = from_nodes[idx_from]
        v = to_nodes[idx_to]

        if u != v:
            edge = tuple(sorted((u, v)))
            if edge not in edges_set:
                edges_set.add(edge)
                count += 1

        idx_from = (idx_from + 1) % len(from_nodes)
        idx_to = (idx_to + 1) % len(to_nodes)

        if count < n_edges and idx_from == 0 and idx_to == 0:
            for i in range(n_edges - count):
                if i < len(from_nodes) and i < len(to_nodes):
                    edges_set.add(tuple(sorted((from_nodes[i], to_nodes[i]))))
            break

    return nodes_set, edges_set


def gen_subgraph(edges_set, n_edges):
    sorted_edges = {tuple(sorted(edge)): edge for edge in edges_set}

    adj_list = collections.defaultdict(set)

    for u, v in set(sorted_edges.keys()):
        adj_list[u].add(v)
        adj_list[v].add(u)

    if len(edges_set) >= n_edges:
        sampled_edges = set(random.sample(list(edges_set), n_edges))
        sampled_nodes = {node for edge in sampled_edges for node in edge}

        return sampled_nodes, sampled_edges

    return None
