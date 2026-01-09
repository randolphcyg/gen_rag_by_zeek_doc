# zeek 知识库基于 dify 生成 rag

当前版本：8.0.4

### 简介
```shell
gen_rag_by_zeek_doc/
├── ext/                        # 拷贝自zeek/doc/ext 
│   ├── conf.py                 # Sphinx 入口配置
│   ├── zeek.py                 # 核心 Domain 定义
│   ├── zeek_pygments.py        # ZeekDomain
│   ├── spicy-pygments.py       # Zeek 代码高亮
│   └── literal-emph.py         # Spicy 语言高亮
├── zeek/                       # 原始 Zeek 源码
│   └── doc/                    # 指向这里读取 RST
├── zeek_docs_markdown/         # 生成目录 (自动生成)
├── zeek_rst_to_rag_md.py       # 基于Sphinx语法解析RST生成dify适配的md文档
└── upload_md_to_dify.py        # 通过dify处理知识库到milvus 【!!当前API hierarchical_model 父子索引类型的无法通过API上传!!】

conf.py 是zeek/doc/ 目录下源文件；
literal-emph.py、spicy-pygments.py、zeek_pygments.py、zeek.py 是zeek/doc/ext 目录下源文件；
zeek_rst_to_rag_md.py 会使用这几个源文件加载zeek自定义的逻辑；
```

### 使用步骤

```shell
当前项目根目录下载zeek仓库，会用到zeek/doc/目录下rst文件；

修改 zeek_rst_to_rag_md.py 中对应环境变量，然后执行解析逻辑，生成zeek_docs_markdown/；

由于【dify父子索引 上传BUG】，当前只能通过 zeek_docs_markdown_flattened.py 将MD文档全部修改名称拷贝到同一层级 zeek_docs_markdown_flattened/ 
然后UI页面一次性上传该目录下所有md文档处理，这种情况下知识库才是父子索引结构；

暂时废弃【修改 upload_md_to_dify.py 环境变量，然后执行dify处理知识库逻辑，向量化存入milvus；】
```
