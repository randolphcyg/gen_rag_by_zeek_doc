import os
import sys
import shutil
import tempfile
import subprocess
import hashlib
from pathlib import Path
from tqdm import tqdm

# ==========================================================
#  全局配置
# ==========================================================

# Zeek 版本 (Tag)
ZEEK_VERSION = "v8.1.0"
ZEEK_REPO_URL = "https://github.com/zeek/zeek.git"

# 路径配置 (使用相对路径，确保在任何地方都能运行)
BASE_DIR = Path(__file__).parent.absolute()
ZEEK_SRC_DIR = BASE_DIR / "zeek_src"      # 下载源码的目录
EXT_DIR = BASE_DIR / "ext"                # 存放 Sphinx 扩展和配置的目录
MD_OUT_DIR = BASE_DIR / "zeek_docs_md"    # 初步转换的 MD 目录
FINAL_OUT_DIR = BASE_DIR / "zeek_docs_flattened" # 最终扁平化的目录

# Sphinx 配置
try:
    from sphinx.application import Sphinx
    from sphinx import addnodes
    from docutils import nodes
except ImportError:
    print("❌ 缺少必要依赖，请运行: pip install sphinx docutils")
    sys.exit(1)

# ==========================================================
#  Step 1: 下载 Zeek 源码
# ==========================================================

def step_download_source():
    print(f"\n🚀 [Step 1] 检查 Zeek 源码 ({ZEEK_VERSION})...")

    if ZEEK_SRC_DIR.exists():
        # 简单检查是否已存在
        print(f"   📂 源码目录已存在: {ZEEK_SRC_DIR}")
        # 如果需要更严谨，可以在这里添加 git checkout 逻辑
        return

    print(f"   📥 正在克隆 Zeek 仓库 (Tag: {ZEEK_VERSION})...")
    try:
        subprocess.run([
            "git", "clone",
            "--depth", "1",
            "--branch", ZEEK_VERSION,
            ZEEK_REPO_URL,
            str(ZEEK_SRC_DIR)
        ], check=True)
        print("   ✅ 克隆完成")
    except subprocess.CalledProcessError as e:
        print(f"   ❌ Git 克隆失败: {e}")
        sys.exit(1)
    except FileNotFoundError:
        print("   ❌ 未找到 git 命令，请安装 git 或手动下载源码到 zeek_src 目录")
        sys.exit(1)

# ==========================================================
#  Step 2: 提取并配置 Extension 环境
# ==========================================================

def step_setup_extensions():
    print(f"\n🛠️ [Step 2] 配置 Sphinx 扩展环境...")

    # 需要提取的文件列表 (源路径相对于 zeek_src)
    # 目标统一放到 ext/ 目录下
    files_to_copy = [
        # (源文件相对路径, 目标文件名)
        ("doc/conf.py", "conf.py"),
        ("doc/ext/zeek.py", "zeek.py"),
        ("doc/ext/zeek_pygments.py", "zeek_pygments.py"),
        ("doc/ext/spicy-pygments.py", "spicy-pygments.py"),
        ("doc/ext/literal-emph.py", "literal-emph.py"),
    ]

    if EXT_DIR.exists():
        shutil.rmtree(EXT_DIR)
    EXT_DIR.mkdir(parents=True, exist_ok=True)

    for src_rel, dest_name in files_to_copy:
        src_path = ZEEK_SRC_DIR / src_rel
        dest_path = EXT_DIR / dest_name

        if not src_path.exists():
            print(f"   ❌ 警告: 未在源码中找到 {src_rel}，跳过")
            continue

        shutil.copy2(src_path, dest_path)
        print(f"   📄 Copied: {src_rel} -> ext/{dest_name}")

    # 【关键】将 ext 目录加入 sys.path，否则 Sphinx 找不到 conf.py 里的扩展
    sys.path.insert(0, str(EXT_DIR))
    print("   ✅ 扩展环境配置完毕")

# ==========================================================
#  Step 3: Sphinx RST -> Markdown 转换核心
# ==========================================================

class MarkdownBuilder:
    def __init__(self):
        self.lines = []
    def add(self, text):
        self.lines.append(text)
    def add_blank(self):
        if self.lines and self.lines[-1].strip() != "":
            self.lines.append("")
    def get_output(self):
        return "\n".join(self.lines)

def process_doctree_to_md(node, builder: MarkdownBuilder, docname="", depth=1):
    # 1. 忽略节点
    if isinstance(node, (nodes.system_message, nodes.comment, addnodes.index, addnodes.productionlist)):
        return

    # 2. 章节递归
    if isinstance(node, nodes.section):
        for child in node.children:
            process_doctree_to_md(child, builder, docname, depth + 1)
        return

    # 3. 标题处理
    if isinstance(node, nodes.title):
        raw_title = node.astext().strip().strip('"').strip("'")
        # 查重逻辑：如果二级标题和文件名完全一致，跳过（避免重复）
        clean_title = raw_title.lower().replace(" ", "")
        clean_docname = docname.lower().replace("-", "").replace("_", "").split("/")[-1] # 只取文件名部分

        if depth == 2 and (clean_title == clean_docname):
            return

        # 降级标题，防止 Dify 切片过于琐碎 (min depth 3 -> H3)
        header_level = min(depth + 1, 6)
        builder.add_blank()
        builder.add(f"{'#' * header_level} {raw_title}")
        builder.add_blank()
        return

    # 4. 段落
    if isinstance(node, nodes.paragraph):
        text = node.astext().replace("\n", " ").strip()
        if text:
            builder.add(text)
            builder.add_blank()
        return

    # 5. 代码块
    if isinstance(node, nodes.literal_block):
        language = node.get("language", "text")
        source_str = str(node.source).lower() if node.source else ""
        if language == "text" and "zeek" in source_str:
            language = "zeek"
        builder.add_blank()
        builder.add(f"```{language}")
        builder.add(node.astext())
        builder.add("```")
        builder.add_blank()
        return

    # 6. 列表
    if isinstance(node, nodes.list_item):
        text = node.astext().replace("\n", " ")
        builder.add(f"- {text}")
        return

    # 7. 表格
    if isinstance(node, nodes.table):
        # 简化的表格处理逻辑
        tgroup = node.next_node(nodes.tgroup)
        if tgroup:
            rows_data = []
            # 获取所有行
            for row in tgroup.findall(nodes.row):
                cells = [entry.astext().strip().replace('\n', ' ') for entry in row.findall(nodes.entry)]
                rows_data.append(" | ".join(cells))

            if rows_data:
                builder.add_blank()
                for r in rows_data:
                    builder.add(f"- {r}")
                builder.add_blank()
        return

    # 8. Zeek 定义域 (Desc)
    if node.__class__.__name__ == "desc":
        builder.add_blank()
        obj_type = node.get("objtype", "Definition")
        for sig in node.findall(addnodes.desc_signature):
            s_text = sig.astext().strip()
            # 使用 H3 触发 Dify 切片
            builder.add(f"### {obj_type}: {s_text}")

        builder.add_blank()
        for child in node.children:
            if not isinstance(child, addnodes.desc_signature):
                process_doctree_to_md(child, builder, docname, depth)
        return

    # 默认递归
    for child in node.children:
        process_doctree_to_md(child, builder, docname, depth + 1)

def step_convert_rst_to_md():
    print(f"\n🔄 [Step 3] 转换 RST 到 Markdown...")

    ZEEK_DOC_ROOT = ZEEK_SRC_DIR / "doc"

    if MD_OUT_DIR.exists():
        shutil.rmtree(MD_OUT_DIR)
    MD_OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 初始化 Sphinx App
    out_tmp = Path(tempfile.mkdtemp())
    doctree_tmp = Path(tempfile.mkdtemp())

    app = Sphinx(
        srcdir=str(ZEEK_DOC_ROOT),
        confdir=str(EXT_DIR), # 指向我们刚刚准备好的 ext 目录
        outdir=str(out_tmp),
        doctreedir=str(doctree_tmp),
        buildername="dummy",
        warningiserror=False,
        verbosity=0,
    )

    print("   📚 构建 doctree (这可能需要几分钟)...")
    app.build(force_all=True)

    docs = sorted(app.env.found_docs)
    print(f"   📄 开始转换 {len(docs)} 个文档...")

    count = 0
    for docname in tqdm(docs, unit="doc"):
        try:
            doctree = app.env.get_doctree(docname)
            builder = MarkdownBuilder()

            # 添加 H1 标题
            clean_name = docname.replace('"', '').replace("'", "").strip().split('/')[-1]
            builder.add(f"# {clean_name}")
            builder.add_blank()

            process_doctree_to_md(doctree, builder, docname=docname)

            # 保存文件
            rel_path = Path(docname + ".md")
            out_path = MD_OUT_DIR / rel_path
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, "w", encoding="utf-8") as f:
                f.write(builder.get_output())
            count += 1
        except Exception as e:
            # 这里的 print 可能会打断进度条，但在出错时是可以接受的
            print(f"❌ Error in {docname}: {e}")

    # 清理临时文件
    shutil.rmtree(out_tmp, ignore_errors=True)
    shutil.rmtree(doctree_tmp, ignore_errors=True)
    print(f"   ✅ 转换完成: {count} 个文件")

# ==========================================================
#  Step 4: 扁平化与重命名 (Fix Dify Issue)
# ==========================================================

def get_safe_filename(filepath: Path, root_dir: Path) -> str:
    MAX_FILENAME_LEN = 240
    try:
        rel_path = filepath.relative_to(root_dir)
        # 将 zeek/api/script.md -> zeek_api_script.md
        full_name = str(rel_path).replace(os.sep, "_").replace("/", "_").replace("\\", "_")
    except ValueError:
        full_name = filepath.name

    if len(full_name.encode('utf-8')) > MAX_FILENAME_LEN:
        # 截断策略
        ext = filepath.suffix
        stem = filepath.stem
        path_hash = hashlib.md5(str(rel_path).encode('utf-8')).hexdigest()[:8]
        safe_name = f"{stem}_{path_hash}{ext}"
        if len(safe_name.encode('utf-8')) > MAX_FILENAME_LEN:
            safe_name = f"doc_{path_hash}{ext}"
        return safe_name
    return full_name

def step_flatten_files():
    print(f"\n📦 [Step 4] 扁平化文件结构 (For Dify)...")

    if FINAL_OUT_DIR.exists():
        shutil.rmtree(FINAL_OUT_DIR)
    FINAL_OUT_DIR.mkdir(parents=True, exist_ok=True)

    files = list(MD_OUT_DIR.glob("**/*.md"))
    print(f"   🔍 扫描到 {len(files)} 个文件，准备拷贝...")

    for f in tqdm(files, unit="file"):
        new_name = get_safe_filename(f, MD_OUT_DIR)
        target = FINAL_OUT_DIR / new_name
        shutil.copy2(f, target)

    print(f"   ✅ 全部完成！输出目录: {FINAL_OUT_DIR}")
    print(f"   💡 现在你可以将此目录下的所有文件上传到 Dify (支持父子索引模式)")

# ==========================================================
#  Main Entry
# ==========================================================

def main():
    print("="*60)
    print(f"   Zeek RAG Builder Automation Tool (Target: {ZEEK_VERSION})")
    print("="*60)

    # 1. 下载源码
    step_download_source()

    # 2. 配置环境 (将 doc/ext 文件移到 ./ext 并加入 path)
    step_setup_extensions()

    # 3. 解析 RST 生成 MD
    step_convert_rst_to_md()

    # 4. 扁平化处理
    step_flatten_files()

if __name__ == "__main__":
    main()