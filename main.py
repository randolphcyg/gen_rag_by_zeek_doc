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
import shutil
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
        if not title_node:
            return

        section_title = title_node.astext()
        
        # 创建新章节
        new_section = {
            "section_id": short_hash(f"{docname}:{'/'.join([s['title'] for s in sections_stack])}:{section_title}"),
            "title": section_title,
            "blocks": [],
            "subsections": []  # 添加子章节列表
        }
        
        # 如果有父章节，添加到父章节的subsections中
        if sections_stack:
            parent_section = sections_stack[-1]
            parent_section["subsections"].append(new_section)
        else:
            # 否则添加到根sections列表
            current_section.append(new_section)
        
        # 将新章节压入堆栈
        sections_stack.append(new_section)
        
        # 处理章节内的所有子节点
        for child in node.children:
            _process_node(child, current_section, docname, symbols, sections_stack)
        
        # 处理完子节点后弹出堆栈
        sections_stack.pop()
    
    # 只处理当前章节内的内容节点
    elif sections_stack:
        current_section_obj = sections_stack[-1]
        
        # 普通文本
        if isinstance(node, nodes.paragraph):
            text = node.astext().strip()
            if text:
                current_section_obj["blocks"].append({
                    "block_id": short_hash(text),
                    "type": "text",
                    "text": text
                })
        
        # 代码块
        elif isinstance(node, nodes.literal_block):
            code = node.astext()
            current_section_obj["blocks"].append({
                "block_id": short_hash(code),
                "type": "code",
                "language": node.get("language"),
                "code": code
            })
        
        # Note / Warning / Tip
        elif isinstance(node, (nodes.note, nodes.warning, nodes.tip)):
            text = node.astext()
            current_section_obj["blocks"].append({
                "block_id": short_hash(text),
                "type": node.__class__.__name__.lower(),
                "text": text
            })
        
        # Zeek Domain 节点
        else:
            cls_name = node.__class__.__name__.lower()
            if cls_name.startswith("zeek"):
                symbols.append({
                    "symbol_id": short_hash(node.astext()),
                    "symbol_type": cls_name,
                    "text": node.astext(),
                    "doc": docname,
                    "section": "/".join([s["title"] for s in sections_stack])
                })


def doctree_to_json(doctree, docname: str, version: str) -> dict:
    doc_json = {
        "doc_id": docname,
        "version": version,
        "title": None,
        "sections": [],
        "symbols": [],
    }

    # 查找文档主标题
    for node in doctree.findall(nodes.title):
        if doc_json["title"] is None:
            doc_json["title"] = node.astext()
            break

    # 使用递归方式处理嵌套章节
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
