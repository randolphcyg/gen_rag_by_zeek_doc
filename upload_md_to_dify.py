import os
import json
import requests
import time
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ===================== 配置区 =====================

DIFY_API_BASE = "http://localhost:5001/v1"
API_KEY = "dataset-MF0p7JRI8hUO5nHXRJ73szfi"
DATASET_ID = "60f859e2-3143-48a9-bbb9-d6d1e5136f26"
DOCS_DIR = r"E:\share\goodjob\gen_rag_by_zeek_doc\zeek_docs_markdown"

MAX_WORKERS = 8

# 数据库通常限制 255，我们设定安全阈值 240
MAX_FILENAME_LEN = 240

# ===================== 核心逻辑 =====================

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

def get_safe_filename(filepath: Path, root_dir: Path) -> str:
    """
    生成符合长度限制的唯一文件名
    """
    try:
        # 1. 尝试生成全路径名: dir_subdir_filename.md
        rel_path = filepath.relative_to(root_dir)
        full_name = str(rel_path).replace(os.sep, "_").replace("/", "_").replace("\\", "_")
    except ValueError:
        full_name = filepath.name

    # 2. 检查长度
    name_len = len(full_name.encode('utf-8')) # 使用 utf-8 字节长度更准确

    # 调试打印（只在接近超长时打印，避免刷屏）
    if name_len > 200:
        print(f"⚠️ [长度预警] {name_len} chars: {full_name}")

    # 3. 如果超长，进行智能截断
    if name_len > MAX_FILENAME_LEN:
        # 策略：保留文件名本身(语义) + 路径的MD5哈希(唯一性) + 扩展名
        # 例如：api.zeek_a1b2c3d4.md
        ext = filepath.suffix  # .md
        stem = filepath.stem   # api.zeek

        # 计算完整路径的 Hash (取前8位)
        path_hash = hashlib.md5(str(rel_path).encode('utf-8')).hexdigest()[:8]

        # 构造新名字
        safe_name = f"{stem}_{path_hash}{ext}"

        # 如果连原文件名都很长，导致 safe_name 依然超长，那就只保留 Hash
        if len(safe_name.encode('utf-8')) > MAX_FILENAME_LEN:
            safe_name = f"doc_{path_hash}{ext}"

        print(f"✂️ [自动截断] 原长 {name_len} -> 新名: {safe_name}")
        return safe_name

    return full_name

def upload_single_file(filepath: Path, root_dir: Path):
    url = f"{DIFY_API_BASE}/datasets/{DATASET_ID}/document/create_by_file"
    headers = {"Authorization": f"Bearer {API_KEY}"}

    # 获取安全的文件名
    unique_name = get_safe_filename(filepath, root_dir)

    data = {
        "indexing_technique": "high_quality",
        "process_rule": json.dumps(PROCESS_RULE),
        "doc_form": "hierarchical_model",
        "doc_language": "English"
    }

    try:
        with open(filepath, 'rb') as f:
            files = {'file': (unique_name, f, 'text/markdown')}
            resp = requests.post(url, headers=headers, data=data, files=files, timeout=60)

            if resp.status_code in [200, 201]:
                return True, unique_name, ""
            else:
                return False, unique_name, f"Status {resp.status_code}: {resp.text}"
    except Exception as e:
        return False, unique_name, str(e)

def main():
    root_path = Path(DOCS_DIR)
    if not root_path.exists():
        print(f"❌ 目录不存在: {DOCS_DIR}")
        return

    files = list(root_path.glob("**/*.md"))
    total_files = len(files)

    print(f"📦 准备并发上传 {total_files} 个文档")
    print(f"📏 最大文件名长度限制: {MAX_FILENAME_LEN} 字符")
    print("-" * 40)

    success_count = 0
    fail_count = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(upload_single_file, f, root_path): f for f in files}

        pbar = tqdm(as_completed(future_to_file), total=total_files, unit="file")

        for future in pbar:
            success, name, error_msg = future.result()

            if success:
                success_count += 1
            else:
                fail_count += 1
                tqdm.write(f"❌ 失败: {name} | {error_msg}")

    print("\n" + "="*40)
    print(f"🎉 处理完成 | 成功: {success_count} | 失败: {fail_count}")

if __name__ == "__main__":
    main()