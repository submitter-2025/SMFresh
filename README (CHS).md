本代码库是论文 "SMFresh: A Verifiable Subgraph Matching Scheme with Freshness Assurance for Outsourced Graph Databases" 的官方实现。

# 1. 环境与依赖

请确保您的环境中已安装 Python 3.9+ 及以下依赖库：
* gmpy2
* networkx
* numpy
* pycryptodome
* sympy
* tqdm

您可以通过 pip 命令进行安装：
`pip install gmpy2 networkx numpy pycryptodome sympy tqdm`

-----------------------------------

# 2. 数据集准备

本实验使用了 Stanford Large Network Dataset Collection (SNAP) 中的真实世界图数据集与基于幂律法则生成的大规模合成图。

1. 运行`ba_generator.py`，将下列数据集下载并解压至项目代码中的`Graphs//`目录下：
   * em: https://snap.stanford.edu/data/email-Enron.txt.gz 
   * db: https://snap.stanford.edu/data/bigdata/communities/com-dblp.ungraph.txt.gz
   * yt: https://snap.stanford.edu/data/bigdata/communities/com-youtube.ungraph.txt.gz
   * pt: https://snap.stanford.edu/data/cit-Patents.txt.gz
   * wt: https://snap.stanford.edu/data/wiki-talk-temporal.txt.gz

2. 分别将 5 份 txt 数据集命名为`snap-Email-Enron.txt`、`snap-com-dblp.txt`、`snap-com-youtube.txt`、`snap-cit-Patents.txt`与`snap-wiki-talk-temporal.txt`。

所有实验的入口文件均为`Triple_Verification.py`。

----------------------------------------------------------------------
场景一：在 'em' 、 'db' 及 'yt' 数据集上开展性能测试
----------------------------------------------------------------------

保持`Triple_Verification.py`文件为默认配置后运行。

*     Line 27: `GDB_INDEX = 0`        （0对应 em 数据集；1对应 db 数据集；2对应 yt 数据集）
*     Line 29: `SUB_INDEX = "3n3e"`   （可选其他查询图）

----------------------------------------------------------------------
场景二：在 'pt' 数据集上开展性能测试
----------------------------------------------------------------------

1. 修改以下变量：
   *     Line 27: GDB_INDEX = 0        ----->   GDB_INDEX = 2
   *     Line 29: SUB_INDEX = "3n3e"   ----->   SUB_INDEX = "5n7e"

2. 取消 Line 30、Line 68、Line 69 的注释以启用基于`sample_size`的图采样。

3. 您现在可以通过修改 Line 30 来控制`pt`数据集的规模。

4. 运行脚本。

----------------------------------------------------------------------
场景三：在 'wt' 数据集上通过控制变量开展性能测试
----------------------------------------------------------------------

1. 撤销场景二中的所有修改。

2. 修改以下变量：
   *     Line 27: GDB_INDEX = 0   ----->   GDB_INDEX = 4
  
3. 注释及取消注释以下内容：
   *     注释 Line 29、Line 33、Line 67、Line 96、Line 268、Line 278、Line 369。
   *     取消注释 Line 28、Line 34、Line 97、Line 269、Line 280、Line 281、Line 370。
  
4. 您现在可以通过修改Line 28、32、34 来控制不同的实验参数。

5. 运行脚本。

6. 修改以下变量：
   *     Line 28: load_temporal_stream(_, _, batch_size=10000)   ----->   load_temporal_stream(_, _, batch_size=1000000)

7. 注释及取消注释以下内容：
   *     注释 Line 52、Line 270、Line 280、Line 500。
   *     取消注释 Line 36、Line 37、Line 38、Line 39、Line 53、LLine 271、Line 279、Line 501。

8. 您现在可以通过修改 Line 27 来控制不同的更新频率。

9. 运行脚本。

----------------------------------------------------------------------
失败案例演示
----------------------------------------------------------------------
您会在主仿真脚本`Triple_Verification.py`中发现几处被标记为“❌ ... FAILURE EXAMPLE ❌”的代码块。

这些部分并非代码错误，而是我们有意设计的内置演示，旨在展示 SMFresh 验证协议的鲁棒性。它们模拟了故障的 CS 可能返回无效结果的三种特定场景。

1. 完整性验证失败案例: 此代码块模拟 CS 返回不存在于图数据库中（人为地将图数据 ID 取反）的查询结果。
2. 新鲜度验证失败案例: 此代码块模拟 CS 使用过时版本的图数据。
3. 正确性验证失败案例: 此代码块模拟 CS 返回一个不完整的结果集（遗漏了部分有效的匹配项）。

----------------------------------------------------------------------

# 开源许可 (License)
本项目采用 MIT 许可。
