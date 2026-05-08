#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Constants module - Global constants and mappings for Nessus Report Generator
"""

from typing import Dict, List, Final


class AppConstants:
    """Application constants"""

    RISK_LEVEL_MAPPING: Final[Dict[str, str]] = {
        "Critical": "超危",
        "High": "高危",
        "Medium": "中危",
        "Low": "低危",
        "Info": "信息",
        "None": "无"
    }

    CSV_ENCODINGS: Final[List[str]] = ['utf-8', 'utf-8-sig', 'gbk', 'gb2312', 'ANSI', 'latin1']

    TARGET_DIR: Final[str] = "./target"
    DEFAULT_OUTPUT_DIR: Final[str] = "./reports/"
    DEFAULT_DB_PATH: Final[str] = "nessus_plugins.db"
    DEFAULT_CONFIG_PATH: Final[str] = "./config/config.ini"
    DEFAULT_LOG_FILE: Final[str] = "nessus_report.log"

    TENABLE_BASE_URL_CN: Final[str] = "https://www.tenablecloud.cn"
    TENABLE_BASE_URL_TW: Final[str] = "https://zh-tw.tenable.com"
    TENABLE_API_PATH: Final[str] = "/_next/data/{build_id}/zh-CN/plugins/search.json"
    TENABLE_API_PATH_TW: Final[str] = "/_next/data/{build_id}/zh-TW/plugins/search.json"
    API_TIMEOUT: Final[int] = 30
    USER_AGENT: Final[str] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )

    TRADITIONAL_TO_SIMPLIFIED: Final[Dict[str, str]] = {
        "嚴重": "严重", "高危": "高危", "中危": "中危", "低危": "低危",
        "主機": "主机", "風險": "风险", "等級": "等级", "數量": "数量",
        "漏洞": "漏洞", "修補": "修补", "建議": "建议",
        "描述": "描述", "詳細": "详细", "資訊": "资讯", "無": "无",
        "安全": "安全", "超危": "超危", "資訊": "信息", "資料": "资料"
    }

    HIGH_RISK_LEVELS: Final[List[str]] = ["Critical", "High"]

    RISK_LEVEL_ORDER: Final[List[str]] = ["Critical", "High", "Medium", "Low", "Info"]

    CHART_COLORS: Final[Dict[str, str]] = {
        '超危': '#e74c3c',
        '高危': '#fd8c00',
        '中危': '#ffeaa7',
        '低危': '#87ceeb',
        '安全': '#C5E0B3',
        '信息': '#C5E0B3'
    }

    CELL_BACKGROUND_COLOR: Final[str] = "D9E2F3"

    CHINESE_FONTS: Final[List[str]] = [
        'SimHei', 'Microsoft YaHei', 'Arial Unicode MS'
    ]
