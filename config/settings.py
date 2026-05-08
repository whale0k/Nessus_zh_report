#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration management module
"""

import configparser
import os
from typing import Optional, Any
from pathlib import Path

from .constants import AppConstants


class ConfigManager:
    """Configuration manager for loading and accessing settings"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or AppConstants.DEFAULT_CONFIG_PATH
        self.config = configparser.ConfigParser()
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from file"""
        if os.path.exists(self.config_path):
            self.config.read(self.config_path, encoding='utf-8')
        else:
            print(f"Warning: Config file '{self.config_path}' not found. Using defaults.")

    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(section, key, fallback=fallback)

    def getboolean(self, section: str, key: str, fallback: bool = False) -> bool:
        """Get boolean configuration value"""
        return self.config.getboolean(section, key, fallback=fallback)

    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        """Get integer configuration value"""
        return self.config.getint(section, key, fallback=fallback)

    def get_list(self, section: str, key: str, fallback: str = '') -> list:
        """Get comma-separated list configuration value"""
        value = self.get(section, key, fallback)
        if not value:
            return []
        return [item.strip() for item in value.split(',') if item.strip()]

    @property
    def db_path(self) -> str:
        """Get database path"""
        return self.get('DEFAULT', '数据库路径', fallback=AppConstants.DEFAULT_DB_PATH)

    @property
    def template_path(self) -> str:
        """Get Word template path"""
        return self.get('DEFAULT', '模板文件路径',
                       fallback='./config/漏洞扫描汇报及修复建议_漏洞排序模板.docx')

    @property
    def output_dir(self) -> str:
        """Get output directory"""
        return self.get('DEFAULT', '输出目录', fallback=AppConstants.DEFAULT_OUTPUT_DIR)

    @property
    def excel_prefix(self) -> str:
        """Get Excel file prefix"""
        return self.get('DEFAULT', 'Excel文件前缀', fallback='漏洞整改表')

    @property
    def word_prefix(self) -> str:
        """Get Word file prefix"""
        return self.get('DEFAULT', 'Word文件前缀', fallback='漏洞扫描汇报及修复建议')

    @property
    def customer_name(self) -> str:
        """Get customer name"""
        return self.get('DEFAULT', '客户名称', fallback='目标企业')

    @property
    def company_name(self) -> str:
        """Get implementation company name"""
        return self.get('DEFAULT', '实施公司', fallback='安全服务公司')

    @property
    def translation_sources(self) -> list:
        """Get translation source priorities"""
        return self.get_list('DEFAULT', '翻译源优先级', fallback='bing,google')

    @property
    def save_translation(self) -> bool:
        """Get whether to save translations to database"""
        return self.getboolean('DEFAULT', '保存翻译结果', fallback=False)

    @property
    def log_file(self) -> str:
        """Get log file path"""
        return self.get('DEFAULT', '日志文件', fallback=AppConstants.DEFAULT_LOG_FILE)

    @property
    def api_timeout(self) -> int:
        """Get API timeout in seconds"""
        return self.getint('DEFAULT', '请求超时时间', fallback=AppConstants.API_TIMEOUT)
