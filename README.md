# 包链显微镜(Pack Chain Microscope)

纯 Rust 实现的 Git pack / index / loose object 取证分析工具:导入文件后保留
内容摘要与原始偏移,解析 pack header、对象类型、ofs-delta、ref-delta、zlib
边界与 index fanout;按 delta 链还原对象并重新计算 Git object id,逐步记录
base、指令范围、输入/输出长度与校验结果。不调用系统 git 完成核心解析。

## 构建与验收

```sh
cargo build --all-targets
cargo test --all-targets
cargo run -- --addr 127.0.0.1:5248
```

打开 http://127.0.0.1:5248 ,页面标题为「包链显微镜」。

所有输入都复制在项目数据目录 `data/incoming/`,SQLite 状态在 `data/microscope.db`。

## 能力

- **解析**:pack v2/v3 header、5 种对象类型、ofs-delta 负偏移距离、ref-delta
  20 字节 base oid、zlib 流边界(`Decompress::total_in`)、idx v2 fanout /
  crc32 / offset / large-offset、loose object 头。
- **还原与校验**:delta copy/insert 指令带完整边界检查;每步 delta 记录
  base 描述、指令字节范围、输入输出长度、base/result size 校验;成功对象重算
  `sha1("type len\0" + content)`;idx 声明 oid 与 CRC 都会交叉核对。
- **故障隔离**:缺外部 base、index 与 pack 不配套、ofs 距离越界、delta 环、
  伪造头部大小、错误 CRC 等均隔离为 blocked/error 并给出证据,其他对象继续分析;
  对象详情页显示完整阻塞链。
- **资源预算**:可配置 delta 深度、总展开字节、单对象展开比例;触顶时对象进入
  `paused` 中间状态(绝不写入部分 content/oid),可在放宽预算或「恢复分析」后重试。
- **局部重算**:补入 base 后只重新解析依赖该 base 的子图(已还原对象走缓存,
  `gen` 代数不变);固定/取消冲突来源(pin)同样只重算子图,形成分析分支。
- **候选确定性**:同一 oid 多候选按(源文件内容摘要, pack 内偏移, 对象 id)
  排序,与导入顺序无关;内容相同的导入文件自动去重。
- **删除保护**:删除源文件前列出该文件对象及其传递依赖,确认后级联失效并重算。
- **页面**:总览统计/预算/证据、源文件与导入、对象列表、对象详情(链/步骤/
  内容预览)、Delta DAG、冲突来源分支。

## 模块

- `src/gitobj.rs` — pack/idx/loose 解析、zlib、delta 应用、object id
- `src/db.rs` — SQLite schema
- `src/engine.rs` — 还原引擎、预算、环检测、阻塞链、导入与局部重算
- `src/web.rs` — Axum 路由与页面
- `tests/e2e.rs` — 自建小 pack 的端到端测试(14 例)
