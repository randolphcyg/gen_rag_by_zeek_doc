import json
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ===================== 配置区 =====================

DIFY_API_BASE = "http://localhost:5001/v1"
API_KEY = "dataset-MF0p7JRI8hUO5nHXRJ73szfi"
DATASET_ID = "ec367307-db47-4449-9624-6e8ae9d6c405"

# 自动定位当前脚本同级的 flattened 目录
BASE_DIR = Path(__file__).parent.absolute()
DOCS_DIR = BASE_DIR / "zeek_docs_flattened"

# 并发数 (建议 4-8，过高会导致 Dify 或 数据库 报错)
MAX_WORKERS = 8

# ===================== 父子索引规则 =====================

PROCESS_RULE = {
    "mode": "hierarchical",
    "rules": {
        "pre_processing_rules": [
            {"id": "remove_extra_spaces", "enabled": True},
            {"id": "remove_urls_emails", "enabled": False}
        ],
        "segmentation": {
            "separator": "\n### ",
            "max_tokens": 1500,
            "chunk_overlap": 50
        },
        "parent_child_indexing": {
            "enabled": True,
            "child_chunk_size": 400,
            "child_chunk_overlap": 100
        }
    }
}

# ===================== 核心逻辑 =====================

def upload_single_file(filepath: Path):
    """
    单个文件上传逻辑
    """
    url = f"{DIFY_API_BASE}/datasets/{DATASET_ID}/document/create_by_file"
    headers = {"Authorization": f"Bearer {API_KEY}"}

    # 直接使用文件名 (因为之前已经处理过安全长度了)
    filename = filepath.name

    data = {
        "indexing_technique": "high_quality",
        "process_rule": json.dumps(PROCESS_RULE),
        "doc_form": "text_model",  # 标准模式，具体的层级由 process_rule 决定
        "doc_language": "English"
    }

    try:
        with open(filepath, 'rb') as f:
            files = {'file': (filename, f, 'text/markdown')}
            # 设置 timeout 防止网络卡死
            resp = requests.post(url, headers=headers, data=data, files=files, timeout=60)

            if resp.status_code in [200, 201]:
                return True, filename, ""
            else:
                return False, filename, f"Status {resp.status_code}: {resp.text[:100]}"
    except Exception as e:
        return False, filename, str(e)

def main():
    if not DOCS_DIR.exists():
        print(f"❌ 目录不存在: {DOCS_DIR}")
        print("   请确保你已经运行了构建脚本，并且文件夹在当前脚本旁边。")
        return

    # 扫描目录下所有的 md 文件 (扁平结构不需要 recursive)
    files = list(DOCS_DIR.glob("*.md"))
    total_files = len(files)

    if total_files == 0:
        print("❌ 目录下没有找到 .md 文件")
        return

    print(f"📦 准备上传 {total_files} 个文档")
    print(f"🚀 并发线程: {MAX_WORKERS}")
    print("-" * 40)

    success_count = 0
    fail_count = 0

    # 使用线程池并发上传
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交任务
        future_to_file = {executor.submit(upload_single_file, f): f for f in files}

        # 使用 tqdm 显示进度条
        pbar = tqdm(as_completed(future_to_file), total=total_files, unit="doc")

        for future in pbar:
            success, name, error_msg = future.result()

            if success:
                success_count += 1
            else:
                fail_count += 1
                # 只有失败时才打印详细信息，避免刷屏
                tqdm.write(f"❌ 失败: {name} | 原因: {error_msg}")

    print("\n" + "="*40)
    print(f"🎉 全部完成!")
    print(f"✅ 成功: {success_count}")
    print(f"❌ 失败: {fail_count}")

if __name__ == "__main__":
    main()