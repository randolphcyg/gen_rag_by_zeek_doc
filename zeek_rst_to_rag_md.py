# main.py
# -----------------------------------------
# Zeek Docs (RST) → Sphinx doctree → Markdown Files
# -----------------------------------------

from sphinx.application import Sphinx
from sphinx import addnodes  # 👈 修复点：导入 Sphinx 专用节点
from docutils import nodes
from pathlib import Path
import tempfile
import sys
import shutil

# 尝试导入 tabulate 用于美化表格
try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ==========================================================
# Sphinx 初始化
# ==========================================================

def build_sphinx_app(srcdir: Path, confdir: Path) -> Sphinx:
    outdir = Path(tempfile.mkdtemp(prefix="zeek_out_"))
    doctreedir = Path(tempfile.mkdtemp(prefix="zeek_doctree_"))

    app = Sphinx(
        srcdir=str(srcdir),
        confdir=str(confdir),
        outdir=str(outdir),
        doctreedir=str(doctreedir),
        buildername="dummy",
        warningiserror=False,
        verbosity=0,
    )
    return app

# ==========================================================
# Markdown 生成核心逻辑
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
    """
    递归遍历 doctree 节点并转换为 RAG 友好的格式 (非标准 Markdown)
    """

    # 1. 忽略的节点
    if isinstance(node, (nodes.system_message, nodes.comment, addnodes.index, addnodes.productionlist)):
        return

    # 2. 章节标题 (Section & Title)
    if isinstance(node, nodes.section):
        for child in node.children:
            process_doctree_to_md(child, builder, docname, depth + 1)
        return

    if isinstance(node, nodes.title):
        title_text = node.astext()

        # 【优化】如果标题和文件名高度相似（忽略大小写和横杠），则跳过不写
        # 例如：文件名 get-started，标题 Get Started -> 跳过
        clean_title = title_text.lower().replace(" ", "")
        clean_docname = docname.lower().replace("-", "").replace("_", "")

        # 只有当它是文档的第一个标题(depth==2)且内容重复时才跳过
        if depth == 2 and (clean_title == clean_docname):
            return

            # 【降级】否则，将其降级为 #### (H4) 或更小，确保在 ### (H3) 之下
        header_level = min(depth + 2, 6)

        builder.add_blank()
        builder.add(f"{'#' * header_level} {title_text}")
        builder.add_blank()
        return

    # 3. 段落 (Paragraph)
    if isinstance(node, nodes.paragraph):
        # 移除换行符，变成一行，方便 Embedding
        text = node.astext().replace("\n", " ").strip()
        if text:
            builder.add(text)
            builder.add_blank()
        return

    # 4. 代码块 (Literal Block)
    if isinstance(node, nodes.literal_block):
        language = node.get("language", "text")
        if language == "text" and "zeek" in str(node.source).lower():
            language = "zeek"
        code_content = node.astext()

        builder.add_blank()
        # 保留代码块标识，这对于 LLM 识别代码很重要
        builder.add(f"```{language}")
        builder.add(code_content)
        builder.add("```")
        builder.add_blank()
        return

    # 5. 列表 (List Item)
    if isinstance(node, nodes.list_item):
        text = node.astext().replace("\n", " ")
        builder.add(f"- {text}")
        return

    # 6. 表格 (Table) -> 【核心修改：扁平化处理】
    if isinstance(node, nodes.table):
        rows = []
        tgroup = node.next_node(nodes.tgroup)
        if tgroup:
            # 提取表头
            headers = []
            thead = tgroup.next_node(nodes.thead)
            if thead:
                for row in thead.findall(nodes.row):
                    headers = [entry.astext().strip() for entry in row.findall(nodes.entry)]

            # 提取内容
            tbody = tgroup.next_node(nodes.tbody)
            if tbody:
                for row in tbody.findall(nodes.row):
                    cells = [entry.astext().strip() for entry in row.findall(nodes.entry)]
                    rows.append(cells)

        if rows:
            builder.add_blank()
            # 策略：如果列数很少(<=3)，做成 Key: Value 形式
            # 如果是复杂表格，还是保留 Markdown 格式，但去掉 ASCII 装饰

            if headers:
                builder.add(f"**Table Data ({', '.join(headers)}):**")
                for row in rows:
                    # 扁平化： "Header1: Value1; Header2: Value2"
                    # 这种格式对 Dify 切分极其友好，切断了也保留了上下文
                    line_items = []
                    for i, cell in enumerate(row):
                        h = headers[i] if i < len(headers) else f"Col{i}"
                        # 去除单元格里的换行
                        clean_cell = cell.replace('\n', ' ')
                        if clean_cell:
                            line_items.append(f"{h}: {clean_cell}")

                    builder.add("- " + "; ".join(line_items))
            else:
                # 没有表头的表格，直接做成列表
                for row in rows:
                    builder.add("- " + " | ".join(row))

            builder.add_blank()
        return

    # 7. Zeek 专用域节点 (desc) -> 【核心修改：作为标题处理】
    if node.__class__.__name__ == "desc":
        builder.add_blank()

        sigs = []
        for sig in node.findall(addnodes.desc_signature):
            sigs.append(sig.astext().strip())

        obj_type = node.get("objtype", "Definition")

        if sigs:
            for s in sigs:
                # 【修改点】不要用 **Zeek type**，改用 ### 标题
                # 这样 Dify 的父子索引会将每个 Zeek 定义视为一个独立的父块！
                builder.add_blank()
                builder.add(f"### {obj_type}: {s}")
                builder.add_blank()

        # 处理描述内容
        for child in node.children:
            if not isinstance(child, addnodes.desc_signature):
                process_doctree_to_md(child, builder, docname, depth)
        return

    # 默认递归
    for child in node.children:
        process_doctree_to_md(child, builder, docname, depth + 1)


# ==========================================================
# 主流程
# ==========================================================

def main():
    # -----------------------------
    # 配置区
    # -----------------------------
    ZEEK_DOC_ROOT = Path(r"E:\share\goodjob\gen_rag_by_zeek_doc\zeek\doc")
    CUSTOM_CONF_DIR = Path(__file__).parent / "ext"
    OUTPUT_DIR = Path(r"E:\share\goodjob\gen_rag_by_zeek_doc\zeek_docs_markdown")

    if not ZEEK_DOC_ROOT.exists():
        print(f"❌ Zeek doc 目录不存在: {ZEEK_DOC_ROOT}")
        sys.exit(1)

    if not (CUSTOM_CONF_DIR / "conf.py").exists():
        print(f"❌ 配置文件不存在: {CUSTOM_CONF_DIR / 'conf.py'}")
        sys.exit(1)

    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("🚀 初始化 Sphinx...")
    app = build_sphinx_app(ZEEK_DOC_ROOT, CUSTOM_CONF_DIR)

    print("📚 构建 doctree...")
    app.build(force_all=True)

    print(f"📄 发现 {len(app.env.found_docs)} 个文档，开始转换...")

    success_count = 0
    for docname in sorted(app.env.found_docs):
        try:
            doctree = app.env.get_doctree(docname)

            builder = MarkdownBuilder()
            builder.add(f"### {docname}") # 添加文件名为一级标题

            process_doctree_to_md(doctree, builder, docname=docname)

            rel_path = Path(docname + ".md")
            out_path = OUTPUT_DIR / rel_path
            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, "w", encoding="utf-8") as f:
                f.write(builder.get_output())

            success_count += 1
            # 减少打印频率，每100个打印一次，防止刷屏
            if success_count % 100 == 0:
                print(f"✅ Converted {success_count} docs...")

        except Exception as e:
            print(f"❌ Failed: {docname} | {e}")
            # 打印更详细的错误堆栈以便排查
            # import traceback
            # traceback.print_exc()

    print("\n🎉 完成！")
    print(f"📦 转换成功：{success_count} / {len(app.env.found_docs)}")
    print(f"📂 输出目录：{OUTPUT_DIR}")

if __name__ == "__main__":
    main()