import os
import shutil
import hashlib
from pathlib import Path
from tqdm import tqdm

# ===================== 配置区 =====================

# 原文档目录
SOURCE_DIR = r"E:\share\goodjob\gen_rag_by_zeek_doc\zeek_docs_markdown"

# 数据库通常限制 255，我们设定安全阈值 240 (保持与上传脚本一致)
MAX_FILENAME_LEN = 240

# ===================== 核心命名逻辑 (完全复用) =====================

def get_safe_filename(filepath: Path, root_dir: Path) -> str:
    """
    生成符合长度限制的唯一文件名 (逻辑与上传脚本完全一致)
    """
    try:
        # 1. 尝试生成全路径名: dir_subdir_filename.md
        rel_path = filepath.relative_to(root_dir)
        # 将路径分隔符转换为下划线
        full_name = str(rel_path).replace(os.sep, "_").replace("/", "_").replace("\\", "_")
    except ValueError:
        full_name = filepath.name

    # 2. 检查长度
    name_len = len(full_name.encode('utf-8')) # 使用 utf-8 字节长度更准确

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

        # 仅在需要截断时打印日志
        # print(f"✂️ [自动截断] {full_name} -> {safe_name}")
        return safe_name

    return full_name

def main():
    source_path = Path(SOURCE_DIR)

    # 1. 确定新文件夹路径 (在源文件夹旁边加上 _flattened 后缀)
    dest_path = source_path.parent / f"{source_path.name}_flattened"

    if not source_path.exists():
        print(f"❌ 源目录不存在: {SOURCE_DIR}")
        return

    # 2. 创建目标文件夹
    if not dest_path.exists():
        os.makedirs(dest_path)
        print(f"📂 创建新文件夹: {dest_path}")
    else:
        print(f"📂 目标文件夹已存在: {dest_path} (新文件将覆盖旧文件)")

    # 3. 扫描所有 md 文件
    print("🔍 正在扫描文件...")
    files = list(source_path.glob("**/*.md"))
    total_files = len(files)
    print(f"📦 找到 {total_files} 个 Markdown 文档")
    print("-" * 50)

    success_count = 0
    fail_count = 0

    # 4. 遍历并拷贝
    pbar = tqdm(files, unit="file")
    for f in pbar:
        try:
            # 获取经过处理的新文件名
            new_name = get_safe_filename(f, source_path)

            # 拼接目标路径
            target_file = dest_path / new_name

            # 执行拷贝 (copy2 会保留文件元数据如修改时间)
            shutil.copy2(f, target_file)

            success_count += 1
        except Exception as e:
            fail_count += 1
            tqdm.write(f"❌ 处理失败: {f.name} | {str(e)}")

    print("\n" + "="*50)
    print(f"🎉 处理完成！")
    print(f"📂 原目录: {source_path}")
    print(f"📂 新目录: {dest_path}")
    print(f"✅ 成功拷贝: {success_count}")
    print(f"❌ 失败: {fail_count}")

if __name__ == "__main__":
    main()