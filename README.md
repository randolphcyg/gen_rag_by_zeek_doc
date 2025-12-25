# zeek doc 生成 rag 到 milvus

### 文件简介
```shell
 gen_rag_by_zeek_doc/
 ├── conf.py                 Sphinx 配置（核心）
 ├── zeek.py                 ZeekDomain（最重要）
 ├── zeek_pygments.py        Zeek 代码高亮
 ├── spicy-pygments.py       Spicy 语言高亮
 ├── literal-emph.py         字面强调扩展
 ├── get_doc_tree.py         # 仅用来查看rst目录树
 ├── to_milvus.py            # 向量化入库逻辑
 └── main.py                 # 基于Sphinx语法解析RST生成json文件

conf.py 是zeek/doc/ 目录下源文件；
literal-emph.py、spicy-pygments.py、zeek_pygments.py、zeek.py 是zeek/doc/ext 目录下源文件；
main.py 会使用这几个源文件加载zeek自定义的逻辑；
```

### 使用

```shell
当前项目根目录下载zeek仓库，会用到zeek/doc/目录下文件；

修改main.py中对应环境变量，然后执行解析逻辑，生成zeek_rag.json；

修改to_milvus.py环境变量，然后执行入库逻辑，向量化存入milvus；
```

### TODO
```shell
开发llm利用rag的逻辑；
```
