"""登记和读取交换资料。"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "materials"


def catalog():
    return json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))


def read_collection(name):
    if name not in catalog():
        raise KeyError(name)
    return json.loads((ROOT / f"{name}.json").read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description="列出或读取本地合成资料")
    parser.add_argument("collection", nargs="?", choices=list(catalog()), metavar="资料名")
    args = parser.parse_args()
    data = read_collection(args.collection) if args.collection else list(catalog())
    print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
