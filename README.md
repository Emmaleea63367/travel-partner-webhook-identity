# 联票回调与对账
这里保管各业务方交换的本地合成资料。编号、地址和身份均为演练专用。
使用 Python 3.11。如当前环境尚未安装依赖，先运行 `python3 -m pip install -r requirements.txt`。

字段定义和外部资料约定见 [资料说明](docs/materials.md)。

```sh
python3 materials.py
python3 materials.py members
python3 -m compileall -q materials.py wireverify.py desk.py tests
python3 -m unittest discover -s tests
python3 -I desk.py
```

资料工具可列出资料集合或读取某一集合。测试核对资料格式、业务引用以及适用的协议样本。

- `wireverify.py` 核验 RFC 9421 消息签名（Ed25519 子集）与 RFC 9530 内容摘要；
- `desk.py` 区分实际签发者、有权声明票款的成员身份与收件端，输出可重复的核账结论。
隔离模式（`python3 -I`）下运行测试可用 `python3 -I -m unittest discover -s tests`，测试文件已自行登记仓库根路径。
