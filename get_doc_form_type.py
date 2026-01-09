import requests
import json
import sys

# ===================== 配置区 =====================

DIFY_API_BASE = "http://localhost:5001/v1"
API_KEY = "dataset-MF0p7JRI8hUO5nHXRJ73szfi"
TARGET_DATASET_ID = "0d0c6918-df07-4541-a619-4e7faf146e0f"

# =================================================

def check_dataset_info():
    url = f"{DIFY_API_BASE}/datasets?page=1&limit=100"

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    print(f"🔍 正在查询知识库信息... ID: {TARGET_DATASET_ID}")

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            print(f"❌ 请求失败: {response.status_code}")
            print(response.text)
            return

        data = response.json()
        datasets = data.get('data', [])

        found = False
        for dataset in datasets:
            if dataset['id'] == TARGET_DATASET_ID:
                found = True
                print("\n✅ 找到目标知识库！")
                print("=" * 40)
                print(f"📛 名称 (Name):      {dataset.get('name')}")
                print(f"🆔 ID:              {dataset.get('id')}")
                print(f"🔑 Doc Form:        【 {dataset.get('doc_form')} 】 <--- 这就是你要填的值")
                print(f"📊 Provider:        {dataset.get('provider')}")
                print(f"📂 Data Source:     {dataset.get('data_source_type')}")
                print("=" * 40)

                # 额外检查：如果是 text_model，API 实际上会忽略 process_rule 里的 hierarchical
                if dataset.get('doc_form') == 'text_model':
                    print("⚠️ 提示: 当前类型为 text_model (通用)。")
                    print("   上传时请在脚本中填写 'doc_form': 'text_model'")
                elif dataset.get('doc_form') == 'hierarchical_model':
                    print("⚠️ 提示: 当前类型为 hierarchical_model (父子索引)。")
                    print("   上传时请在脚本中填写 'doc_form': 'hierarchical_model'")
                break

        if not found:
            print(f"❌ 未在列表中找到 ID 为 {TARGET_DATASET_ID} 的知识库。")
            print("   可能是 API Key 权限不足，或 ID 拼写错误。")
            print(f"   当前 API Key 能看到 {len(datasets)} 个知识库。")

    except Exception as e:
        print(f"💥 发生错误: {str(e)}")

if __name__ == "__main__":
    check_dataset_info()