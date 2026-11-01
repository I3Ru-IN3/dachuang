# DNS 流量采集与粗筛（filtering）

本目录实现基于 Scapy 的 DNS 流量采集、字段归一化、分组、热/冷过滤器与定时检测。
本次重构以架构与模块边界为主：DNS 筛选条件、分桶/淘汰策略和示例检测规则保持原有语义，
只顺带修复明确的机械缺陷（见第 7 节）。

## 1. 目录结构

```text
filtering/
├── Filtering.py              # 兼容入口：python Filtering.py / python -m filtering.Filtering
├── __init__.py               # 使 filtering 可作为包导入
├── config.yaml               # 运行配置
├── config_loader.py          # 旧版单例配置加载器（保留兼容，新代码不再使用）
├── dns_filter/               # 重构后的实现
│   ├── __init__.py           # 对外公开 API
│   ├── models.py             # DnsInfo / FilterStats 数据模型
│   ├── dns_parser.py         # DNS 包校验、字段提取、RData 解码
│   ├── output.py             # CSV 输出
│   ├── grouping.py           # PacketGrouper：按数量/超时聚合
│   ├── filters.py            # ColdFilter、BurstFilterEngine、快照
│   ├── detection.py          # 检测策略、告警输出、定时检测器
│   ├── config.py             # 类型化配置与校验
│   ├── logging_setup.py      # 显式初始化日志
│   ├── capture.py            # 在线/离线抓包适配
│   ├── service.py            # 组合根：装配各层并管理生命周期
│   └── cli.py                # 命令行入口
└── tests/                    # unittest 测试
```

## 2. 分层职责

| 层 | 模块 | 职责 |
|---|---|---|
| 数据模型 | `models.py` | `DnsInfo` 是层间唯一的数据契约；不依赖 Scapy、线程或配置 |
| 解析 | `dns_parser.py` | 判断包是否合格、提取域名/TTL/RData、按记录类型解码载荷 |
| 输入 | `capture.py` | 解析网卡、组装 Scapy `sniff` 参数、在线/离线分支 |
| 聚合 | `grouping.py` | 只负责“何时刷新缓冲区”，通过回调把批次交给过滤器 |
| 过滤 | `filters.py` | 唯一持有热/冷过滤器可变状态的层：热桶、桶计数、冷过滤器 |
| 检测 | `detection.py` | 检测策略与定时调度分离；检测时使用快照，不持有过滤器锁 |
| 配置 | `config.py` | YAML → 类型化 dataclass，路径解析与启动前校验 |
| 编排 | `service.py` | 依赖注入、线程启停、最终 flush、运行统计 |
| 入口 | `cli.py` | 参数解析、日志初始化、错误码与终端输出 |

依赖方向大致为：

```text
cli -> service -> {capture, grouping, filters, detection, config}
grouping -> dns_parser -> models
filters  -> dns_parser, models
detection -> models
```

解析、聚合、过滤、检测都不再读取全局配置，也不依赖模块级可变全局变量。

## 3. 数据流

```text
sniff / 离线 pcap
  └─ FilteringService.add_packet(pkt)
       └─ PacketGrouper.add(pkt)
            ├─ is_valid_dns_packet(pkt)          # 单包快速过滤
            ├─ buffer.append(pkt)
            └─ 达到 group_size 或超时
                 └─ flush()
                      ├─ extract_dns_info(batch) -> list[DnsInfo]
                      └─ BurstFilterEngine.add_dnsinfos(infos)
                           ├─ 按 Registered_Domain 分组
                           ├─ xxhash32 -> 桶索引
                           ├─ 同域追加 / 冲突淘汰
                           └─ 被淘汰数据 -> ColdFilter

PeriodicDetector
  └─ 定时获取 burst_infos() / cold_infos() 快照
       └─ PayloadSizeDetector.detect(snapshot)
            └─ DetectionSink.emit(detection)
```

检测不再在 `filer_lock` 下遍历全部数据；它拿到的是 `burst_infos()`/`cold_infos()` 生成的
列表快照。这样检测耗时不会阻塞抓包线程的过滤器写入。

## 4. 运行方式

在仓库根目录：

```bash
python filtering/Filtering.py
python filtering/Filtering.py --config filtering/config.yaml

# 也可以按包运行
python -m filtering.Filtering
```

在 `filtering/` 目录内：

```bash
python Filtering.py
```

配置路径优先级：

1. 命令行 `--config PATH`；
2. 环境变量 `DNS_FILTER_CONFIG`；
3. 默认 `filtering/config.yaml`（基于模块位置解析，不依赖当前工作目录）。

旧入口名仍然可用：

```python
from Filtering import PacketGrouper, BurstFilterEngine, extract_dns_info
```

## 5. 配置

当前实际使用的配置项：

```yaml
capture:
  offline_mode: true
  pcap_file: "filtering/noise.pcapng"
  interface_index: 19       # 在线模式使用
  timeout: 120              # 0 表示不限制
  packet_count: 0           # 0 表示不限制
  filter: ""                # BPF 表达式

logging:
  enabled: true
  level: INFO
  file: "sniffer.log"
  max_bytes: 10485760
  backup_count: 5
```

说明：

- `timeout: 0` 会转换为 Scapy 的 `timeout=None`（不限制），不会像旧实现那样立即结束；
- 相对路径会依次尝试“配置文件目录、当前工作目录、filtering 目录、项目根目录”；
- 输出文件（如日志）尚不存在时，`filtering/...` 形式按项目根目录解析，其余按配置文件目录解析；
- `analysis` 段目前仅保留为历史配置，运行逻辑尚未使用。

## 6. 测试

```bash
python -m unittest discover -s filtering/tests -v
```

测试覆盖：

- DNS 包校验与 `PacketList`/生成器/单包输入；
- 各记录类型 RData 解码、CSV 输出；
- 热桶同域追加、冲突淘汰、冷过滤器、容量软上限、输入列表不被排序修改；
- 分组按数量/超时触发、关闭时最终 flush、回调异常计数；
- 检测阈值、定时检测器、日志/打印输出；
- 配置解析、路径解析与启动校验；
- `FilteringService` 的解析→过滤装配。

## 7. 本次架构调整的边界

保持原语义的部分：

- DNS 保留条件：IP/UDP/DNS、存在 Answer、`qdcount == 1`、qname 可解码；
- 注册域仍取域名最后两段（未引入公共后缀库）；
- 热桶容量仍是“软上限”（达到上限后当前整组仍可进入）；
- 冲突淘汰仍使用原来的确定性 `hash % ingest_count` 概率；
- 示例检测规则仍是 `payload_size > 100`，输出文案不变。

顺带修复的机械缺陷（不改变算法设计）：

- 冲突替换时 `bucket.clear` 未调用的问题；
- `filter_dns_packets` 只接受 `list`、不接受 Scapy `PacketList` 的问题；
- 在线模式忽略已解析接口、硬编码接口索引的问题；
- 离线模式仍强制解析网卡的问题；
- `registered_domain` 在无 Question 时未初始化的问题；
- CSV 表头与实际字段不一致的问题；
- 抓包结束后未 flush 尾批数据的问题；
- 日志初始化从导入副作用改为显式启动步骤。

未在本次范围内处理（留给后续逻辑/性能迭代）：

- 冷过滤器无上限、无 TTL、未落盘；
- `rdpcap` 一次性加载大文件，未改为 `PcapReader` 流式读取；
- 公共后缀（如 `co.uk`）的注册域识别；
- 检测规则的策略化扩展（DGA、DNS 隧道、高频查询等）；
- 更细粒度的按桶锁/读写锁与指标导出。

## 8. 依赖

- Python 3
- `scapy`
- `xxhash`
- `PyYAML`
- `rich`（旧代码使用；新核心路径不再依赖，保留以兼容现有环境）
