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
COLLECTION_NAME = "zeek_rag_v8_0_4"  # 建议版本号入库名

JSON_FILE_PATH = r"G:\share\goodjob\gen_rag_by_zeek_doc\modify_zeek_rag.json"

OLLAMA_HOST = "http://localhost:11434"
OLLAMA_MODEL = "nomic-embed-text:latest"
EMBEDDING_DIM = 768

BATCH_SIZE_EMBEDDING = 8
BATCH_SIZE_MILVUS = 200

# 字节数限制（Milvus VARCHAR 以字节计）
MAX_BYTES_RAW = 8000
MAX_BYTES_CLEAN = 6000

# ===================== 处理类 =====================
class ZeekMilvusPusher:

    def __init__(self):
        self.milvus_client = MilvusClient(uri=f"http://{MILVUS_HOST}:{MILVUS_PORT}")
        self._check_ollama_health()

    def _check_ollama_health(self):
        try:
            resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=5)
            resp.raise_for_status()
        except:
            raise RuntimeError(f"Ollama 服务未启动或无法连接: {OLLAMA_HOST}")

    def create_collection(self):
        if self.milvus_client.has_collection(COLLECTION_NAME):
            logger.warning(f"删除旧集合: {COLLECTION_NAME}")
            self.milvus_client.drop_collection(COLLECTION_NAME)

        schema = self.milvus_client.create_schema(auto_id=True, primary_field_name="pk")

        # 定义字段
        schema.add_field("pk", DataType.INT64, is_primary=True)
        schema.add_field("partition_tag", DataType.VARCHAR, max_length=50) # p_logs, p_reference 等
        schema.add_field("doc_id", DataType.VARCHAR, max_length=500)
        schema.add_field("doc_title", DataType.VARCHAR, max_length=500)
        schema.add_field("section_title", DataType.VARCHAR, max_length=500)
        schema.add_field("content_type", DataType.VARCHAR, max_length=50)  # text, code, symbol
        schema.add_field("raw_content", DataType.VARCHAR, max_length=MAX_BYTES_RAW)
        schema.add_field("embedding", DataType.FLOAT_VECTOR, dim=EMBEDDING_DIM)
        schema.add_field("update_time", DataType.INT64)

        index_params = self.milvus_client.prepare_index_params()
        index_params.add_index(
            field_name="embedding",
            index_type="IVF_FLAT",
            metric_type="COSINE",
            params={"nlist": 128}
        )

        self.milvus_client.create_collection(
            collection_name=COLLECTION_NAME,
            schema=schema,
            index_params=index_params
        )
        logger.info(f"成功创建 Collection: {COLLECTION_NAME}")

    def _safe_truncate(self, text: str, max_bytes: int) -> str:
        if not text: return ""
        text = text.replace("\x00", "").strip()
        encoded = text.encode("utf-8")
        if len(encoded) <= max_bytes:
            return text
        return encoded[:max_bytes].decode("utf-8", errors="ignore")

    def _get_embedding(self, texts: list):
        # 批量获取 Embedding
        resp = requests.post(
            f"{OLLAMA_HOST}/api/embed",
            json={"model": OLLAMA_MODEL, "input": texts},
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()["embeddings"]

    def _iter_sections(self, sections, parents=None):
        if parents is None: parents = []
        for sec in sections:
            full_title = " > ".join(parents + [sec["title"]])
            # 提取本级 blocks
            for block in sec.get("blocks", []):
                yield full_title, block
            # 递归子级
            if sec.get("subsections"):
                yield from self._iter_sections(sec["subsections"], parents + [sec["title"]])

    def process(self):
        with open(JSON_FILE_PATH, "r", encoding="utf-8") as f:
            all_docs = json.load(f)

        pending_records = []

        for doc in tqdm(all_docs, desc="解析文档内容"):
            doc_meta = {
                "partition_tag": doc.get("partition", "p_guides"),
                "doc_id": doc["doc_id"],
                "doc_title": doc["title"],
                "update_time": int(time.time())
            }

            # 1. 处理章节中的内容
            for sec_title, block in self._iter_sections(doc["sections"]):
                content = ""
                if block["type"] == "code":
                    content = f"Code block ({block.get('language','')}):\n{block.get('code','')}"
                else:
                    content = block.get("text", "")

                if not content or len(content) < 10: continue

                pending_records.append({
                    **doc_meta,
                    "section_title": sec_title,
                    "content_type": block["type"],
                    "raw_content": self._safe_truncate(content, MAX_BYTES_RAW)
                })

            # 2. 处理独立的 Symbols (高价值 API 定义)
            for sym in doc.get("symbols", []):
                sym_text = f"Zeek {sym['symbol_type']} definition: {sym['text']}"
                pending_records.append({
                    **doc_meta,
                    "section_title": sym.get("section", "API Reference"),
                    "content_type": "symbol",
                    "raw_content": self._safe_truncate(sym_text, MAX_BYTES_RAW)
                })

        logger.info(f"解析完成，准备生成向量并入库，总 Chunk 数: {len(pending_records)}")

        # 3. 批量向量化并入库
        for i in tqdm(range(0, len(pending_records), BATCH_SIZE_MILVUS), desc="入库进度"):
            batch = pending_records[i : i + BATCH_SIZE_MILVUS]

            # Ollama 批量 Embedding 逻辑 (针对 batch 内部再次切分避免超载)
            texts_to_embed = [r["raw_content"][:3000] for r in batch] # 限制 embedding 文本长度

            try:
                embeddings = []
                for j in range(0, len(texts_to_embed), BATCH_SIZE_EMBEDDING):
                    sub_batch = texts_to_embed[j : j + BATCH_SIZE_EMBEDDING]
                    embeddings.extend(self._get_embedding(sub_batch))

                for record, emb in zip(batch, embeddings):
                    record["embedding"] = emb

                self.milvus_client.insert(collection_name=COLLECTION_NAME, data=batch)
            except Exception as e:
                logger.error(f"批量入库失败: {e}")

        logger.info("🎉 所有数据已推送至 Milvus!")

if __name__ == "__main__":
    pusher = ZeekMilvusPusher()
    pusher.create_collection()
    pusher.process()