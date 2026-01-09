# zeek rst基于 dify 生成 rag

### 文件简介
```shell
 gen_rag_by_zeek_doc/
 ├── ext                        # 拷贝自zeek/doc/ext   
 |    ├── conf.py               # Sphinx 配置
 |    ├── zeek.py               # ZeekDomain
 |    ├── zeek_pygments.py      # Zeek 代码高亮
 |    ├── spicy-pygments.py     # Spicy 语言高亮
 |    └── literal-emph.py       # 字面强调扩展
 ├── doc_rst_tree.py           # 仅用来查看rst目录树
 ├── sync_zeek_docs_to_dify.py # 通过dify处理知识库
 └── zeek_rst_to_rag_md.py     # 基于Sphinx语法解析RST生成dify适配的md文档


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
└── upload_md_to_dify.py        # 通过dify处理知识库到milvus 【当前API hierarchical_model 父子索引类型的无法通过API上传】

conf.py 是zeek/doc/ 目录下源文件；
literal-emph.py、spicy-pygments.py、zeek_pygments.py、zeek.py 是zeek/doc/ext 目录下源文件；
zeek_rst_to_rag_md.py 会使用这几个源文件加载zeek自定义的逻辑；
```

### 使用

```shell
当前项目根目录下载zeek仓库，会用到zeek/doc/目录下rst文件；

修改 zeek_rst_to_rag_md.py中对应环境变量，然后执行解析逻辑，生成zeek_docs_markdown/；

修改 upload_md_to_dify.py环境变量，然后执行dify处理知识库逻辑，向量化存入milvus；

当前只能通过 zeek_docs_markdown_flattened.py 将MD文档全部修改名称拷贝到同一层级 然后UI页面一次性上传处理 【父子索引 上传BUG】
```
