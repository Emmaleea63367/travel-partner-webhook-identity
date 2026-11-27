# 联票回调与对账
这里保管各业务方交换的本地合成资料。编号、地址和身份均为演练专用。
使用 Python 3.11。如当前环境尚未安装依赖，先运行 `python3 -m pip install -r requirements.txt`。

字段定义和外部资料约定见 [资料说明](docs/materials.md)。

```sh
python3 materials.py
python3 materials.py members
python3 -m compileall -q materials.py tests
python3 -m unittest discover -s tests
```

资料工具可列出资料集合或读取某一集合。测试核对资料格式、业务引用以及适用的协议样本。
