import os
import pickle
import time


class Timer:
    def __init__(self):
        self.start = 0

    def tick(self):
        self.start = time.perf_counter()

    def tock(self):
        return (time.perf_counter() - self.start) * 1000


class CacheManager:
    CACHE_DIR = "Cache"

    DATASET_MAP = {0: "Email", 1: "DBLP",
                   2: "Youtube", 3: "Patents",
                   4: "Wiki-Talk", 5: "Synthetic"}

    def __init__(self):
        if not os.path.exists(self.CACHE_DIR):
            os.makedirs(self.CACHE_DIR)

    def key_path(self):
        return os.path.join(self.CACHE_DIR, "Keys.pkl")

    def data_path(self, idx, init_ratio, scale=None):
        GDB = self.DATASET_MAP.get(idx, f"DB{idx}")

        if scale is not None:
            GDB_NAME = f"Enc_{GDB}_Scale_{int(scale)}_Q_{SUB_IDX}.pkl"
        elif init_ratio < 1.0:
            GDB_NAME = f"Enc_{GDB}_Stream_{init_ratio}.pkl"
        else:
            GDB_NAME = f"Enc_{GDB}_Full.pkl"

        return os.path.join(self.CACHE_DIR, GDB_NAME)

    @staticmethod
    def save(data, path):
        with open(path, "wb") as f:
            pickle.dump(data, f)

    @staticmethod
    def load(path):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return pickle.load(f)
        return None

# ------------------------------------------------------------
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
GDB_DIR = os.path.join(BASE_DIR, "GDB") + os.sep

GDB_NAMES = ["snap-Email-Enron.txt",
             "snap-com-dblp.txt",
             "snap-com-youtube.txt",
             "snap-cit-Patents.txt",
             "snap-wiki-talk-temporal.txt",
             "synthetic_graph_1M_nodes.txt"]

SUBGRAPHS = {"snap-Email-Enron.txt":
                 {"3n3e": [[{1, 3, 4},
                            {(1, 3), (1, 4), (3, 4)}]],
                  "5n4e": [[{1, 3, 4, 6, 8552},
                            {(1, 3), (1, 4), (3, 6), (4, 8552)}]],
                  "5n6e": [[{1, 3, 4, 5, 56},
                            {(1, 3), (1, 4), (1, 5), (1, 56), (3, 4), (5, 56)}]],
                  "5n7e": [[{1, 3, 4, 878, 8552},
                            {(1, 3), (1, 4), (3, 4), (3, 878), (3, 8552), (4, 8552), (878, 8552)}]],
                  "6n6e": [[{1, 56, 70, 1139, 2015, 10601},
                            {(1, 56), (1, 70), (56, 2015), (70, 10601), (1139, 2015), (1139, 10601)}]],
                  "6n8e": [[{1, 3, 4, 5, 56, 74},
                            {(1, 3), (1, 4), (1, 5), (1, 56), (3, 4), (4, 74), (5, 56), (56, 74)}]]},

             "snap-com-dblp.txt":
                 {"3n3e": [[{0, 1, 2},
                            {(0, 1), (0, 2), (1, 2)}]],
                  "5n4e": [[{0, 1, 2, 6786, 17411},
                            {(0, 1), (0, 2), (1, 17411), (2, 6786)}]],
                  "5n6e": [[{0, 1, 2, 23073, 274042},
                            {(0, 1), (0, 2), (0, 23073), (0, 274042), (1, 2), (23073, 274042)}]],
                  "5n7e": [[{0, 1, 2, 4519, 75503},
                            {(0, 1), (0, 2), (0, 4519), (0, 75503), (1, 2), (2, 75503), (4519, 75503)}]],
                  "6n6e": [[{0, 12220, 14652, 35367, 101215, 274042},
                            {(0, 101215), (0, 274042), (12220, 14652), (12220, 35367), (14652, 101215), (35367, 274042)}]],
                  "6n8e": [[{0, 1, 2, 33043, 33971, 90680},
                            {(0, 1), (0, 2), (0, 33043), (0, 33971), (1, 2), (1, 90680), (33043, 33971), (33971, 90680)}]]},

             "snap-com-youtube.txt":
                 {"3n3e": [[{1, 2, 4},
                           {(1, 2), (1, 4), (2, 4)}]],
                  "5n4e": [[{1, 2, 3, 514, 9312},
                           {(1, 2), (1, 3), (2, 514), (3, 9312)}]],
                  "5n6e": [[{1, 2, 4, 514, 2059},
                           {(1, 2), (1, 4), (2, 4), (2, 514), (2, 2059), (514, 2059)}]],
                  "5n7e": [[{1, 2, 4, 514, 2059},
                           {(1, 2), (1, 4), (2, 4), (2, 514), (2, 2059), (4, 514), (514, 2059)}]],
                  "6n6e": [[{1, 22, 376, 1490, 8084, 86015},
                           {(1, 22), (1, 376), (22, 8084), (376, 86015), (1490, 8084), (1490, 86015)}]],
                  "6n8e": [[{1, 2, 4, 376, 514, 2059},
                           {(1, 2), (1, 4), (1, 376), (2, 4), (2, 514), (2, 2059), (376, 514), (514, 2059)}]]},

             "snap-cit-Patents.txt":
                 {"5n7e": [[{2560875, 3006102, 5438788, 5832654, 5950347},
                           {(2560875, 5438788), (2560875, 5832654), (3006102, 5438788), (3006102, 5832654), (3006102, 5950347), (5438788, 5832654), (5438788, 5950347)}]],
                  "6n8e": [[{4126446, 4364770, 4486227, 4765599, 4892580, 4906292},
                           {(4126446, 4364770), (4126446, 4486227), (4126446, 4765599), (4364770, 4486227), (4364770, 4765599), (4486227, 4765599), (4486227, 4892580), (4486227, 4906292)}]]}}

# ------------------------------------------------------------
# ------------------------------------------------------------

GDB_IDX = 0
INITIAL_RATIO = 1

BATCH_SIZE = 10000
N_ROUNDS = 67

TIMESTAMP_SIZE = 20

SUB_IDX = "3n3e"
QUERY_INTERVAL = 1
