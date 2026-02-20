# 🛡️ SMFresh: A Verifiable Subgraph Matching Scheme with Freshness Assurance

<p align="left">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
</p>

> **Note:** This repository is the official implementation of the paper *"SMFresh: A Verifiable Subgraph Matching Scheme with Freshness Assurance for Outsourced Graph Databases"*.

SMFresh is a lightweight, strictly **output-sensitive** framework for secure and verifiable subgraph matching over dynamically updated graph databases. It provides rigorous cryptographic guarantees for <span style="color:#E53935">**Integrity**</span>, <span style="color:#1E88E5">**Freshness**</span>, and <span style="color:#43A047">**Correctness**</span> under the split-trust threat model.

---

## ⚙️ 1. Environment and Dependencies

Please ensure that you have **Python 3.8+** installed. The cryptographic operations (like BN128 pairings and RSA) require specific mathematical libraries. 

Install the required dependencies using `pip`:

```bash
pip install numpy sympy py_ecc tqdm
```

---

## 📂 2. Dataset Preparation

This experiment relies on real-world graph datasets from the Stanford Large Network Dataset Collection ([SNAP](https://snap.stanford.edu/)) and large-scale synthetic graphs based on power-law distributions.

### Download & Extraction
Please download the following datasets, extract them, and place them into the `GDB/` directory in the project root:

| Alias | Dataset Name | Download Link | Target Filename (Rename to) |
| :--- | :--- | :--- | :--- |
| **em** | Email-Enron | [Download .gz](https://snap.stanford.edu/data/email-Enron.txt.gz) | `snap-Email-Enron.txt` |
| **db** | DBLP | [Download .gz](https://snap.stanford.edu/data/bigdata/communities/com-dblp.ungraph.txt.gz) | `snap-com-dblp.txt` |
| **yt** | Youtube | [Download .gz](https://snap.stanford.edu/data/bigdata/communities/com-youtube.ungraph.txt.gz) | `snap-com-youtube.txt` |
| **pt** | Patents | [Download .gz](https://snap.stanford.edu/data/cit-Patents.txt.gz) | `snap-cit-Patents.txt` |
| **wt** | Wiki-Talk | [Download .gz](https://snap.stanford.edu/data/wiki-talk-temporal.txt.gz) | `snap-wiki-talk-temporal.txt` |
| **sy** | Synthetic | Generated locally | `synthetic_graph_1M_nodes.txt` |

---

## 🚀 3. Quick Start & Reproducing Experiments

The entry file for all experiments is now **`Main.py`**, which is fully controllable via arguments. For automated batch testing to reproduce the paper's figures, simply use the provided **`RUN.sh`** script.

### 📍 Scenario 1: Performance on `em`, `db`, and `yt`
*(Corresponding to **Fig. 6** in the paper)*

To test the basic query performance across standard datasets, run:
```bash
./RUN.sh fig6
```
> **What this does:** It iterates over datasets 0 (em), 1 (db), and 2 (yt) using predefined query topologies (e.g., `3n3e`, `5n6e`) with a default batch size of 5,000.

### 📍 Scenario 2: Scalability Stress-test on `pt`
*(Corresponding to **Fig. 7** in the paper)*

To test how SMFresh resists data volume explosions on the massive Patents graph (scaling from 20k to 2.56M nodes), run:
```bash
./RUN.sh fig7
```
> **What this does:** It automatically triggers the `--scale` argument in `Main.py` to incrementally sample and build the graph, recording the strictly output-sensitive verification times.

### 📍 Scenario 3: Sensitivity Analysis on Dynamic Streams (`wt` & `sy`)
*(Corresponding to **Fig. 10 & Fig. 11** in the paper)*

To conduct a controlled-variable analysis (varying Batch Size, Temporal Structure Size, and Query Size) on temporal graphs:
```bash
# For Wiki-Talk (wt)
./RUN.sh fig10

# For Synthetic Graph (sy)
./RUN.sh fig11
```
> **What this does:** It fixes specific variables while sweeping others (e.g., varying batch sizes from 500 to 320k) to demonstrate the amortization effects and system throughput.

---

## 🛠️ 4. Advanced Usage (Manual Execution)

If you want to run a specific test case without the shell script, you can use `Main.py` directly:

```bash
python Main.py \
    --dataset 0 \
    --init_ratio 1.0 \
    --batch_size 5000 \
    --ts_size 20 \
    --query 3n3e \
    --rounds 10 \
    --interval 1
```

**Key Arguments:**
* `--dataset`: Dataset index (0: em, 1: db, 2: yt, 3: pt, 4: wt, 5: sy).
* `--init_ratio`: Use `< 1.0` to simulate chronological stream replays.
* `--query`: Target topology (e.g., `5n7e`, `6n8e`).

---

## 🛑 5. Security & Failure Handling

SMFresh is mathematically designed to fail fast and loudly when under attack. The core logic resides in `Logic_Check.py`. 

If the untrusted Cloud Server (CS) attempts to:
1. <span style="color:#E53935">**Break Integrity:**</span> Return forged graphs not anchored to the DO's AA-MHT root...
2. <span style="color:#1E88E5">**Break Freshness:**</span> Replay a historically valid state ($t_{old}$) instead of the DO's latest broadcast epoch ($t_k$)...
3. <span style="color:#43A047">**Break Correctness:**</span> Lazily omit valid subgraphs, failing the RSA Oblivious PSI check against the $\mathit{GCF}$...

The verification functions (`verify_integrity` and `TSFVP_PSICVP`) will strictly evaluate to `False` and immediately terminate the system (`sys.exit(1)`), thwarting the attack.

---

## 📄 6. License

This project is licensed under the **MIT License**.