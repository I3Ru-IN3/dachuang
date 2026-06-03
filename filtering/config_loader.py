import os
import yaml

class Config:
    """配置管理类，单例模式（可选）"""
    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load(self, config_path="config.yaml"):
        """加载配置文件"""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"配置文件不存在: {config_path}")
        with open(config_path, 'r', encoding='utf-8') as f:
            self._config = yaml.safe_load(f)
        return self._config

    def get(self, key, default=None):
        """获取配置项，支持点号分隔的路径，例如 'capture.interface'"""
        if self._config is None:
            raise RuntimeError("配置未加载，请先调用 load()")
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        return value

# 全局配置对象
config = Config()