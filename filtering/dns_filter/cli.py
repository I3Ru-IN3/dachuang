"""Command-line entry point for the DNS filtering pipeline."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from .config import AppConfig, ConfigError
from .logging_setup import configure_logging
from .service import FilteringService

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="filtering",
        description="基于 Scapy 的 DNS 流量采集、粗筛与定时检测",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help="配置文件路径；默认使用 filtering/config.yaml，也可通过 DNS_FILTER_CONFIG 指定",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = AppConfig.load(args.config)
    except (ConfigError, OSError) as exc:
        print(f"配置错误: {exc}", file=sys.stderr)
        return 2

    configure_logging(config.logging)
    logger.info("使用配置文件: %s", config.source_path)

    service = FilteringService(config)
    try:
        stats = service.run()
    except KeyboardInterrupt:
        logger.warning("用户中断，正在退出")
        service.close()
        return 130
    except Exception:
        logger.exception("运行失败")
        service.close()
        return 1

    print(
        f"抓包结束，共处理 {stats.packets_received} 个数据包，"
        f"提取 {stats.infos_extracted} 条 DNS 记录"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
