from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dns_filter.config import AppConfig, ConfigError, PROJECT_DIR, resolve_config_path
from support import temporary_directory


class ConfigTest(unittest.TestCase):
    def test_from_mapping_resolves_relative_paths(self):
        with temporary_directory() as directory:
            base = Path(directory)
            pcap = base / "sample.pcap"
            pcap.write_bytes(b"")
            raw = {
                "capture": {
                    "offline_mode": True,
                    "pcap_file": "sample.pcap",
                    "timeout": 12.5,
                    "packet_count": 7,
                    "filter": "udp port 53",
                },
                "logging": {
                    "enabled": True,
                    "level": "debug",
                    "file": "filter.log",
                    "max_bytes": 1024,
                    "backup_count": 2,
                },
            }
            config = AppConfig.from_mapping(
                raw,
                source_path=base / "config.yaml",
                base_dir=base,
            )

            self.assertEqual(config.capture.pcap_file, pcap.resolve())
            self.assertEqual(config.capture.timeout, 12.5)
            self.assertEqual(config.capture.packet_count, 7)
            self.assertEqual(config.capture.bpf_filter, "udp port 53")
            self.assertEqual(config.logging.level, "DEBUG")
            self.assertEqual(config.logging.file, (base / "filter.log").resolve())
            config.validate()

    def test_output_path_with_filtering_prefix_uses_project_root(self):
        with temporary_directory() as directory:
            config = AppConfig.from_mapping(
                {"logging": {"file": "filtering/output.log"}},
                base_dir=directory,
            )
            self.assertEqual(
                config.logging.file,
                (PROJECT_DIR / "filtering" / "output.log").resolve(),
            )

    def test_offline_mode_requires_existing_pcap(self):
        config = AppConfig.from_mapping({"capture": {"offline_mode": True}})
        with self.assertRaises(ConfigError):
            config.validate()

        with temporary_directory() as directory:
            missing = Path(directory) / "missing.pcap"
            config = AppConfig.from_mapping(
                {"capture": {"offline_mode": True, "pcap_file": str(missing)}}
            )
            with self.assertRaises(ConfigError):
                config.validate()

    def test_online_mode_requires_interface(self):
        config = AppConfig.from_mapping({"capture": {"offline_mode": False}})
        with self.assertRaises(ConfigError):
            config.validate()

    def test_negative_timeout_is_rejected(self):
        config = AppConfig.from_mapping({"capture": {"timeout": -1}})
        with self.assertRaises(ConfigError):
            config.validate()

    def test_invalid_boolean_is_rejected(self):
        with self.assertRaises(ConfigError):
            AppConfig.from_mapping({"capture": {"offline_mode": "maybe"}})

    def test_invalid_log_level_is_rejected(self):
        config = AppConfig.from_mapping({"logging": {"level": "LOUD"}})
        with self.assertRaises(ConfigError):
            config.validate()

    def test_section_must_be_mapping(self):
        with self.assertRaises(ConfigError):
            AppConfig.from_mapping({"capture": []})

    def test_root_must_be_mapping(self):
        with self.assertRaises(ConfigError):
            AppConfig.from_mapping([])  # type: ignore[arg-type]

    def test_resolve_explicit_missing_path(self):
        with self.assertRaises(ConfigError):
            resolve_config_path("definitely-not-here.yaml")

    def test_resolve_env_path(self):
        with temporary_directory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text("capture: {}\n", encoding="utf-8")
            with patch.dict(os.environ, {"DNS_FILTER_CONFIG": str(path)}, clear=False):
                self.assertEqual(resolve_config_path(), path.resolve())


if __name__ == "__main__":
    unittest.main()
