import re
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple


class ZeekDocForcedParser:
    def __init__(self, doc_root: str):
        self.doc_root = Path(doc_root).resolve()
        self.root_index = self.doc_root / "index.rst"
        self.hierarchy_order: List[Dict] = []  # 按顺序存储层级信息
        self.all_files_ordered: List[Path] = []  # 按解析顺序的文件路径
        self.visited: Set[Path] = set()

        # 超宽松的 toctree 匹配规则（兼容 Zeek 的任意格式）
        self.toctree_start_pattern = re.compile(r"^\.\. toctree::", re.MULTILINE | re.IGNORECASE)
        self.toctree_entry_loose_pattern = re.compile(r"(?<=\n)\s+([a-zA-Z0-9_\-/]+)(?=\s|$)", re.MULTILINE)

    def _read_rst(self, rst_path: Path) -> Optional[str]:
        """读取 rst 文件，兼容编码错误"""
        try:
            return rst_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                return rst_path.read_text(encoding="gbk")
            except:
                print(f"⚠️  无法读取 {rst_path}（编码不支持）")
                return None
        except Exception as e:
            print(f"⚠️  读取 {rst_path} 失败：{e}")
            return None

    def _extract_all_possible_entries(self, rst_content: str) -> List[str]:
        """
        暴力提取所有可能的 toctree 条目（兼容 Zeek 任意格式）
        步骤：1. 找到 toctree 块 2. 提取所有符合路径规则的条目
        """
        entries = []
        if not self.toctree_start_pattern.search(rst_content):
            return entries

        # 分割内容为 toctree 块和非块部分
        lines = rst_content.splitlines()
        in_toctree = False
        for line in lines:
            line_stripped = line.strip()
            # 进入 toctree 块
            if line_stripped.startswith(".. toctree::"):
                in_toctree = True
                continue
            # 退出 toctree 块（遇到空行/其他指令）
            if in_toctree and (not line_stripped or line_stripped.startswith(".. ") or line_stripped.startswith(":")):
                if line_stripped and not line_stripped.startswith(":"):  # 非选项行则退出
                    in_toctree = False
                else:
                    continue
            # 提取块内条目
            if in_toctree:
                match = self.toctree_entry_loose_pattern.search("\n" + line)
                if match:
                    entry = match.group(1).strip()
                    if entry and not entry.startswith((':', '#', '..')):
                        entries.append(entry)
        # 去重并保留顺序
        seen = set()
        return [e for e in entries if e not in seen and not seen.add(e)]

    def _resolve_entry_strict(self, parent_rst: Path, entry: str) -> Tuple[Optional[Path], bool]:
        """
        严格解析条目路径（覆盖 Zeek 所有场景）
        返回：(目标文件路径, 是否是目录节点)
        """
        parent_dir = parent_rst.parent
        entry_clean = entry.strip().replace("/index", "")

        # 场景1：entry 是 "xxx/index" → 找 xxx/index.rst
        if entry.endswith("/index"):
            target = parent_dir / entry_clean / "index.rst"
            if target.exists():
                return target.resolve(), True

        # 场景2：entry 是 "xxx" → 先找 xxx.rst，再找 xxx/index.rst
        target1 = parent_dir / f"{entry_clean}.rst"
        if target1.exists():
            return target1.resolve(), False

        target2 = parent_dir / entry_clean / "index.rst"
        if target2.exists():
            return target2.resolve(), True

        # 场景3：直接是带后缀的文件
        target3 = parent_dir / entry_clean
        if target3.exists() and target3.suffix == ".rst":
            return target3.resolve(), False

        return None, False

    def _recursive_force_parse(self, current_rst: Path, level: int = 0, parent_path: str = ""):
        """
        强制递归解析，即使没有 toctree 也会检查子目录
        :param current_rst: 当前解析的 rst 文件
        :param level: 层级深度（用于缩进）
        :param parent_path: 父层级路径（如 "devel/spicy"）
        """
        # 避免重复解析
        if current_rst in self.visited:
            return
        self.visited.add(current_rst)
        self.all_files_ordered.append(current_rst)

        # 记录当前层级信息
        rel_path = current_rst.relative_to(self.doc_root)
        current_level_path = str(rel_path.parent).replace("\\", "/") if rel_path.parent != Path(".") else ""
        self.hierarchy_order.append({
            "level": level,
            "path": str(rel_path).replace("\\", "/"),
            "parent": parent_path,
            "is_dir_node": "index.rst" in str(rel_path) and rel_path.parent.name != "doc"
        })

        # 读取并提取 toctree 条目
        content = self._read_rst(current_rst)
        if not content:
            return

        entries = self._extract_all_possible_entries(content)
        if not entries:
            # 兜底：即使没有 toctree，也检查当前目录下的 index.rst 子目录
            current_dir = current_rst.parent
            for sub_dir in current_dir.iterdir():
                if sub_dir.is_dir():
                    sub_index = sub_dir / "index.rst"
                    if sub_index.exists() and sub_index not in self.visited:
                        self._recursive_force_parse(sub_index, level + 1, str(rel_path).replace("\\", "/"))
            return

        # 按条目顺序递归解析
        for entry in entries:
            target_rst, is_dir_node = self._resolve_entry_strict(current_rst, entry)
            if not target_rst:
                # 最后兜底：直接拼接路径尝试
                fallback = self.doc_root / entry.replace("/index", "")
                if fallback.exists():
                    target_rst = fallback.resolve()
                else:
                    continue

            # 递归下一层
            child_parent = str(rel_path).replace("\\", "/")
            self._recursive_force_parse(target_rst, level + 1, child_parent)

    def parse(self):
        """执行强制解析"""
        if not self.root_index.exists():
            raise FileNotFoundError(f"根文件不存在：{self.root_index}")

        print(f"🔍 强制递归解析根文件：{self.root_index}")
        self._recursive_force_parse(self.root_index)

    def print_complete_hierarchy(self):
        """打印完整的层级结构（带缩进）"""
        print("\n=== 📋 Zeek 文档完整层级（强制递归解析）===")
        for item in self.hierarchy_order:
            indent = "  " * item["level"]
            node_type = "📂" if item["is_dir_node"] else "📄"
            print(f"{indent}{node_type} {item['path']} (父节点：{item['parent'] or 'root'})")

    def print_file_list(self):
        """打印按顺序的所有文件路径（可直接用于解析）"""
        print("\n=== 📄 按解析顺序的所有文件路径 ===")
        for idx, file in enumerate(self.all_files_ordered, 1):
            print(f"{idx:4d} | {file}")

    def get_file_list(self) -> List[str]:
        """返回按顺序的文件路径字符串列表（方便后续调用）"""
        return [str(f) for f in self.all_files_ordered]


if __name__ == "__main__":
    # 现在zeek doc原素材合并到仓库 克隆仓库切换到lts分支即可看到\zeek\doc目录
    DOC_ROOT = r"G:\share\goodjob\gen_rag_by_zeek_doc\zeek\doc"

    # 初始化并执行解析
    parser = ZeekDocForcedParser(DOC_ROOT)
    try:
        parser.parse()
        # 打印层级结构
        parser.print_complete_hierarchy()
        # 打印文件列表
        parser.print_file_list()
        # 获取文件列表（后续解析用）
        file_list = parser.get_file_list()
        print(f"\n✅ 解析完成！共找到 {len(file_list)} 个 rst 文件")
    except Exception as e:
        print(f"❌ 解析失败：{e}")