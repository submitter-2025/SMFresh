import networkx as nx


n = 1_000_000
m = 5

output_filename = "synthetic_graph_1M_nodes.txt"

G = nx.barabasi_albert_graph(n, m).to_undirected()

nx.write_edgelist(G, output_filename, data=False, encoding='utf-8')
