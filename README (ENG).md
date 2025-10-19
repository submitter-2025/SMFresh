This repository is the official implementation of the paper "SMFresh: A Verifiable Subgraph Matching Scheme with Freshness Assurance for Outsourced Graph Databases".

# 1. Environment and Dependencies

Please ensure that you have Python 3.9+ and the following dependencies installed in your environment:
* gmpy2
* networkx
* numpy
* pycryptodome
* sympy
* tqdm

You can install them using the pip command:
`pip install gmpy2 networkx numpy pycryptodome sympy tqdm`

-----------------------------------

# 2. Dataset Preparation

This experiment uses real-world graph datasets from the Stanford Large Network Dataset Collection (SNAP) and large-scale synthetic graphs generated based on the power-law distribution.

1. Run `ba_generator.py`, and download and extract the following datasets to the `Graphs//` directory in the project code:
   * em: https://snap.stanford.edu/data/email-Enron.txt.gz 
   * db: https://snap.stanford.edu/data/bigdata/communities/com-dblp.ungraph.txt.gz
   * yt: https://snap.stanford.edu/data/bigdata/communities/com-youtube.ungraph.txt.gz
   * pt: https://snap.stanford.edu/data/cit-Patents.txt.gz
   * wt: https://snap.stanford.edu/data/wiki-talk-temporal.txt.gz

2. Rename the 5 txt datasets respectively as `snap-Email-Enron.txt`、`snap-com-dblp.txt`、`snap-com-youtube.txt`、`snap-cit-Patents.txt`与`snap-wiki-talk-temporal.txt`.

The entry file for all experiments is `Triple_Verification.py`.

----------------------------------------------------------------------
Scenario 1: Conduct performance tests on the 'em', 'db', and 'yt' datasets
----------------------------------------------------------------------

Run the `Triple_Verification.py` file with its default configuration.

*     Line 27: `GDB_INDEX = 0`        (0 corresponds to the em dataset; 1 to the db dataset; 2 to the yt dataset)
*     Line 29: `SUB_INDEX = "3n3e"`   (other query graphs can be selected)

----------------------------------------------------------------------
Scenario 2: Conduct performance tests on the 'pt' dataset
----------------------------------------------------------------------

1. Modify the following variables:
   *     Line 27: GDB_INDEX = 0        ----->   GDB_INDEX = 2
   *     Line 29: SUB_INDEX = "3n3e"   ----->   SUB_INDEX = "5n7e"

2. Uncomment Lines 30, 68, and 69 to enable graph sampling based on `sample_size`.

3. You can now control the scale of the `pt` dataset by modifying Line 30.

4. Run the script.

----------------------------------------------------------------------
Scenario 3: Conduct performance tests on the 'wt' dataset by controlling variables
----------------------------------------------------------------------

1. Revert all changes made in Scenario 2.

2. Modify the following variables:
   *     Line 27: GDB_INDEX = 0   ----->   GDB_INDEX = 4
  
3. Comment and uncomment the following content:
   *     Comment out Lines 29, 33, 67, 96, 268, 278, and 369.
   *     Uncomment Lines 28, 34, 97, 269, 280, 281, and 370.
  
4. You can now control different experimental parameters by modifying Lines 28, 32, and 34.

5. Run the script.

6. Modify the following variables:
   *     Line 28: load_temporal_stream(_, _, batch_size=10000)   ----->   load_temporal_stream(_, _, batch_size=1000000)

7. Comment and uncomment the following content:
   *     Comment out Lines 52, 270, 280, and 500.
   *     Uncomment Lines 36, 37, 38, 39, 53, 271, 279, and 501.

8. You can now control different update frequencies by modifying Line 27.

9. Run the script.

----------------------------------------------------------------------
Failure Case Demonstration
----------------------------------------------------------------------
You will find several code blocks marked with “❌ ... FAILURE EXAMPLE ❌” in the main simulation script `Triple_Verification.py`.

These sections are not code errors but are intentionally designed built-in demonstrations to showcase the robustness of the SMFresh verification protocol. They simulate three specific scenarios where a faulty CS might return invalid results.
1. Integrity Verification Failure Case: This code block simulates the CS returning a query result that does not exist in the graph database (by artificially negating the graph data ID).
2. Freshness Verification Failure Case: This code block simulates the CS using an outdated version of the graph data.
3. Correctness Verification Failure Case: This code block simulates the CS returning an incomplete result set (omitting some valid matches).

----------------------------------------------------------------------

# License
This project is licensed under the MIT License.
