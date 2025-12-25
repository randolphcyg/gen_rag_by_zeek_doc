import os
import time
import json
import requests
import logging
from tqdm import tqdm
from pymilvus import MilvusClient, DataType
from pymilvus.milvus_client import IndexParams

# ===================== 日志配置 =====================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ===================== 核心配置 =====================
MILVUS_HOST = "localhost"
MILVUS_PORT = 19530
COLLECTION_NAME = "zeek_docs_v804_V6"

JSON_FILE_PATH = r"G:\share\goodjob\gen_rag_by_zeek_doc\zeek_rag.json"

OLLAMA_HOST = "http://localhost:11434"
OLLAMA_MODEL = "nomic-embed-text:latest"
EMBEDDING_DIM = 768

BATCH_SIZE_EMBEDDING = 4
BATCH_SIZE_MILVUS = 500

MAX_SINGLE_TEXT_LEN = 10000
MAX_BATCH_TOTAL_LEN = 8000

MILVUS_CLEAN_MAX_LEN = 5500
MILVUS_RAW_MAX_LEN = 7000


# ===================== 处理类 =====================
class ZeekJsonProcessor:

    def __init__(self):
        self.embedding_dim = EMBEDDING_DIM
        self.milvus_client = MilvusClient(uri=f"http://{MILVUS_HOST}:{MILVUS_PORT}")
        self._drop_old_collection()
        self._check_ollama_health()

    # -----------------------------
    # 基础设施
    # -----------------------------

    def _drop_old_collection(self):
        if self.milvus_client.has_collection(COLLECTION_NAME):
            logger.warning(f"删除旧集合 {COLLECTION_NAME}")
            self.milvus_client.drop_collection(COLLECTION_NAME)

    def _check_ollama_health(self):
        resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=10)
        resp.raise_for_status()
        if not any(m["name"] == OLLAMA_MODEL for m in resp.json()["models"]):
            raise RuntimeError(f"模型不存在：{OLLAMA_MODEL}")

    def _sanitize_text(self, text: str) -> str:
        if not text:
            return ""

        # 去掉 NULL 字符
        text = text.replace("\x00", "")

        # 去掉极端空白
        text = text.strip()
        if not text:
            return ""

        # 硬限制长度（字符级）
        return text[:6000]

    def _filter_text(self, text: str):
        if not text:
            return ""
        return text.strip()[:MAX_SINGLE_TEXT_LEN]

    # -----------------------------
    # Embedding
    # -----------------------------

    def _embed_batch(self, texts):
        payload = {
            "model": OLLAMA_MODEL,
            "input": texts
        }
        resp = requests.post(
            f"{OLLAMA_HOST}/api/embed",
            json=payload,
            timeout=60
        )

        if resp.status_code != 200:
            raise RuntimeError(
                f"Ollama embed failed: {resp.status_code}, {resp.text[:200]}"
            )

        return resp.json()["embeddings"]

    def batch_generate_embeddings(self, texts):
        embeddings = []

        for i in tqdm(range(0, len(texts), BATCH_SIZE_EMBEDDING), desc="生成向量"):
            batch_raw = texts[i:i+BATCH_SIZE_EMBEDDING]
            batch = [self._sanitize_text(t) for t in batch_raw]

            # 全空直接跳过
            if not any(batch):
                embeddings.extend([[]] * len(batch))
                continue

            try:
                embs = self._embed_batch(batch)
                embeddings.extend(embs)
            except Exception as e:
                logger.warning(f"⚠️ batch embedding 失败，降级为单条: {e}")

                # 降级为单条
                for text in batch:
                    if not text:
                        embeddings.append([])
                        continue
                    try:
                        single = self._embed_batch([text])[0]
                        embeddings.append(single)
                    except Exception as se:
                        logger.error(f"❌ 单条 embedding 失败，跳过: {text[:80]}")
                        embeddings.append([])

        return embeddings

    # -----------------------------
    # Milvus
    # -----------------------------

    def create_collection(self):
        schema = self.milvus_client.create_schema(
            auto_id=True,
            primary_field_name="doc_id"
        )
        schema.add_field("doc_id", DataType.INT64, is_primary=True)
        schema.add_field("doc_version", DataType.VARCHAR, max_length=20)
        schema.add_field("doc_path", DataType.VARCHAR, max_length=500)
        schema.add_field("doc_title", DataType.VARCHAR, max_length=200)
        schema.add_field("doc_section", DataType.VARCHAR, max_length=200)
        schema.add_field("raw_content", DataType.VARCHAR, max_length=8000)
        schema.add_field("clean_content", DataType.VARCHAR, max_length=10000)
        schema.add_field("update_time", DataType.INT64)
        schema.add_field(
            "content_embedding",
            DataType.FLOAT_VECTOR,
            dim=self.embedding_dim,
            metric_type="COSINE"
        )

        self.milvus_client.create_collection(
            collection_name=COLLECTION_NAME,
            schema=schema,
            consistency_level="Bounded"
        )

        index_params = IndexParams()
        index_params.add_index("content_embedding", index_type="IVF_FLAT", metric_type="COSINE")
        self.milvus_client.create_index(COLLECTION_NAME, index_params)

    def _truncate_for_milvus(self, text: str, max_len: int) -> str:
        if not text:
            return ""
        text = text.replace("\x00", "").strip()
        if len(text) > max_len:
            return text[:max_len]
        return text

    # 递归遍历章节，展开所有子章节
    def _iter_sections(self, sections, parents=None):
        if parents is None:
            parents = []

        for section in sections or []:
            title = section.get("title", "") or ""
            current_titles = parents + ([title] if title else [])
            section_path = " / ".join(t for t in current_titles if t)

            for block in section.get("blocks", []):
                yield section_path, block

            yield from self._iter_sections(section.get("subsections", []), current_titles)


    def batch_insert(self, records):
        safe_records = []

        for r in records:
            r["raw_content"] = self._safe_truncate_bytes(
                r.get("raw_content", ""),
                MILVUS_RAW_MAX_LEN
            )
            r["clean_content"] = self._safe_truncate_bytes(
                r.get("clean_content", ""),
                MILVUS_CLEAN_MAX_LEN
            )

            emb = r.get("content_embedding")
            if not emb or len(emb) != EMBEDDING_DIM:
                continue

            safe_records.append(r)

        if not safe_records:
            return

        self.milvus_client.insert(COLLECTION_NAME, safe_records)
        self.milvus_client.flush(COLLECTION_NAME)

    # -----------------------------
    # JSON → Chunk → Milvus
    # -----------------------------

    def _safe_truncate_bytes(self, text: str, max_bytes: int) -> str:
        """
        按 UTF-8 字节数裁剪，确保 Milvus VARCHAR 不越界
        """
        if not text:
            return ""

        text = text.replace("\x00", "").strip()
        raw = text.encode("utf-8")

        if len(raw) <= max_bytes:
            return text

        # 逐步回退，直到字节数合法
        truncated = raw[:max_bytes]
        while True:
            try:
                return truncated.decode("utf-8")
            except UnicodeDecodeError:
                truncated = truncated[:-1]

    def _truncate_for_embedding(self, text: str) -> str:
        """
        给 embedding 用的强裁剪（token 友好）
        """
        if not text:
            return ""

        # nomic-embed-text 实测：4k chars 左右比较安全
        SAFE_EMBED_CHAR_LEN = 3500

        text = text.replace("\x00", "").strip()
        if len(text) <= SAFE_EMBED_CHAR_LEN:
            return text

        # 优先按段落截断
        parts = text.split("\n\n")
        out = []
        total = 0

        for p in parts:
            if total + len(p) > SAFE_EMBED_CHAR_LEN:
                break
            out.append(p)
            total += len(p)

        return "\n\n".join(out)[:SAFE_EMBED_CHAR_LEN]

    def _merge_blocks_by_section(self, doc):
        merged = {}

        for section_path, block in self._iter_sections(doc.get("sections", [])):
            key = section_path or doc.get("title", "")

            if key not in merged:
                merged[key] = []

            if block.get("type") == "code":
                merged[key].append(
                    f"\n```{block.get('language','')}\n{block.get('code','')}\n```"
                )
            else:
                merged[key].append(block.get("text", ""))

        results = {}
        for section, parts in merged.items():
            text = "\n\n".join(parts).strip()

            # 🚨 防止巨无霸 section
            if len(text) > 12000:
                text = text[:12000]

            results[section] = text

        return results


    def load_and_process_json(self):
        with open(JSON_FILE_PATH, "r", encoding="utf-8") as f:
            docs = json.load(f)

        logger.info(f"加载 {len(docs)} 篇 Zeek 文档")

        chunks = []

        for doc in docs:
            doc_path = doc["doc_id"]
            doc_title = doc.get("title", "")
            doc_version = doc.get("version", "Zeek 8.0.4")

            merged_sections = self._merge_blocks_by_section(doc)

            for section_path, merged_text in merged_sections.items():
                raw_text = self._safe_truncate_bytes(
                    merged_text,
                    MILVUS_RAW_MAX_LEN
                )

                embed_text = self._truncate_for_embedding(raw_text)
                if not embed_text:
                    continue

                clean_text = self._safe_truncate_bytes(
                    embed_text,
                    MILVUS_CLEAN_MAX_LEN
                )

                chunks.append({
                    "doc_version": doc_version,
                    "doc_path": doc_path,
                    "doc_title": doc_title,
                    "doc_section": section_path,
                    "raw_content": raw_text,
                    "clean_content": clean_text,
                    "update_time": int(time.time())
                })

        logger.info(f"拆分得到 {len(chunks)} 个语义块")

        # === 后续 embedding / milvus 不变 ===
        texts = [c["clean_content"] for c in chunks]
        embeddings = self.batch_generate_embeddings(texts)

        records = []
        for meta, emb in zip(chunks, embeddings):
            if not emb or len(emb) != EMBEDDING_DIM:
                continue
            records.append({**meta, "content_embedding": emb})

            if len(records) >= BATCH_SIZE_MILVUS:
                self.batch_insert(records)
                records = []

        if records:
            self.batch_insert(records)

        self.milvus_client.load_collection(COLLECTION_NAME)
        stats = self.milvus_client.get_collection_stats(COLLECTION_NAME)
        logger.info(f"✅ 入库完成，共 {stats['row_count']} 条")

    def run(self):
        self.create_collection()
        self.load_and_process_json()


# ===================== 入口 =====================
if __name__ == "__main__":
    processor = ZeekJsonProcessor()
    processor.run()
