# main.py
# -----------------------------------------
# Zeek Docs → Sphinx doctree → RAG JSON
# -----------------------------------------

from sphinx.application import Sphinx
from docutils import nodes

from pathlib import Path
import tempfile
import json
import hashlib
import sys


# ==========================================================
# 工具函数
# ==========================================================

def short_hash(text: str, length: int = 12) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()[:length]


# ==========================================================
# Sphinx 初始化
# ==========================================================

def build_sphinx_app(srcdir: Path) -> Sphinx:
    """
    创建一个最小 Sphinx App：
    - 加载 conf.py
    - 加载 ZeekDomain / pygments
    - 不生成 HTML
    """

    outdir = Path(tempfile.mkdtemp(prefix="zeek_out_"))
    doctreedir = Path(tempfile.mkdtemp(prefix="zeek_doctree_"))

    app = Sphinx(
        srcdir=str(srcdir),
        confdir=str(srcdir),          # conf.py 所在目录
        outdir=str(outdir),
        doctreedir=str(doctreedir),
        buildername="dummy",          # 👈 关键：只构建 doctree
        warningiserror=False,
        verbosity=0,
    )

    return app


# ==========================================================
# doctree → JSON
# ==========================================================

def _process_node(node, current_section, docname, symbols, sections_stack):
    """
    递归处理文档树节点，支持嵌套章节
    """
    # 处理章节标题
    if isinstance(node, nodes.section):
        title_node = node.next_node(nodes.title)
        if not title_node: return
        section_title = title_node.astext()

        new_section = {
            "section_id": short_hash(f"{docname}:{section_title}"),
            "title": section_title,
            "blocks": [],
            "subsections": []
        }
        if sections_stack:
            sections_stack[-1]["subsections"].append(new_section)
        else:
            current_section.append(new_section)

        sections_stack.append(new_section)
        for child in node.children:
            if not isinstance(child, nodes.title): # 避免标题重复进入 blocks
                _process_node(child, current_section, docname, symbols, sections_stack)
        sections_stack.pop()

    elif sections_stack:
        current_section_obj = sections_stack[-1]
        cls_name = node.__class__.__name__.lower()

        # 1. 普通文本
        if isinstance(node, nodes.paragraph):
            text = node.astext().strip()
            if text:
                current_section_obj["blocks"].append({"block_id": short_hash(text), "type": "text", "text": text})

        # 2. 代码块
        elif isinstance(node, nodes.literal_block):
            code = node.astext()
            current_section_obj["blocks"].append({
                "block_id": short_hash(code), "type": "code",
                "language": node.get("language", "text"), "code": code
            })

        # 3. 表格处理 (优化语义)
        elif isinstance(node, nodes.table):
            rows = []
            for row in node.findall(nodes.row):
                cells = [cell.astext().strip() for cell in row.findall(nodes.entry)]
                if len(cells) >= 2:
                    rows.append(f"- {cells[0]}: {cells[1]}")
            if rows:
                table_text = f"Data structure in {docname}:\n" + "\n".join(rows)
                current_section_obj["blocks"].append({
                    "block_id": short_hash(table_text), "type": "table", "text": table_text
                })

        # 4. Zeek 专用符号 (统一合并)
        elif cls_name.startswith("zeek"):
            sym_text = node.astext().strip()
            if sym_text:
                # 存入 symbols 列表
                symbols.append({
                    "symbol_id": short_hash(sym_text),
                    "symbol_type": cls_name,
                    "text": sym_text,
                    "section": sections_stack[-1]["title"]
                })
                # 同时存入 blocks 确保可被检索
                current_section_obj["blocks"].append({
                    "block_id": short_hash(sym_text), "type": "zeek_symbol", "text": f"Zeek {cls_name}: {sym_text}"
                })


def doctree_to_json(doctree, docname: str, version: str) -> dict:
    # 路径感知分区逻辑
    partition = "p_guides"
    if "logs/" in docname: partition = "p_logs"
    elif "script-reference" in docname or "frameworks" in docname: partition = "p_reference"

    features = {"has_api": False, "has_cli": False, "has_code": False, "has_table": False}
    for node in doctree.findall():
        c = node.__class__.__name__.lower()
        if c.startswith("zeek"): features["has_api"] = True
        if isinstance(node, nodes.literal_block):
            features["has_code"] = True
            if node.get("language") in ["console", "bash"]: features["has_cli"] = True
            if partition == "p_guides" and "install" in docname: partition = "p_ops" # 动态提升
        if isinstance(node, nodes.table): features["has_table"] = True

    doc_json = {
        "doc_id": docname,
        "partition": partition, # 👈 最终分区的关键字段
        "version": version,
        "features": features,
        "title": docname, # 默认标题
        "sections": [],
        "symbols": [],
    }

    # 找到第一个真正的顶级标题
    for node in doctree.findall(nodes.title):
        doc_json["title"] = node.astext()
        break

    sections_stack = []
    for node in doctree.children:
        _process_node(node, doc_json["sections"], docname, doc_json["symbols"], sections_stack)

    return doc_json


# ==========================================================
# 主流程
# ==========================================================

def main():
    """
    主入口
    """

    # -----------------------------
    # 根据你的环境修改
    # -----------------------------
    # 现在zeek doc原素材合并到仓库 克隆仓库切换到lts分支即可看到\zeek\doc目录
    ZEEK_DOC_ROOT = Path(r"G:\share\goodjob\gen_rag_by_zeek_doc\zeek\doc")
    OUTPUT_JSON = "zeek_rag.json"
    ZEEK_VERSION = "Zeek 8.0.4"

    if not ZEEK_DOC_ROOT.exists():
        print(f"❌ Zeek doc 目录不存在: {ZEEK_DOC_ROOT}")
        sys.exit(1)

    print("🚀 初始化 Sphinx（加载 Zeek Domain & 扩展）...")
    app = build_sphinx_app(ZEEK_DOC_ROOT)

    print("📚 构建 doctree（不生成 HTML）...")
    app.build(force_all=True)

    results = []

    print(f"📄 共发现 {len(app.env.found_docs)} 个文档")
    for docname in sorted(app.env.found_docs):
        try:
            doctree = app.env.get_doctree(docname)
            doc_json = doctree_to_json(doctree, docname, ZEEK_VERSION)
            results.append(doc_json)
            print(f"✅ Parsed: {docname}")
        except Exception as e:
            print(f"❌ Failed: {docname} | {e}")

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("\n🎉 完成！")
    print(f"📦 文档数：{len(results)}")
    print(f"🧠 输出文件：{OUTPUT_JSON}")

    # 可选：清理临时目录（如需要）
    # shutil.rmtree(app.outdir, ignore_errors=True)
    # shutil.rmtree(app.doctreedir, ignore_errors=True)


if __name__ == "__main__":
    main()
