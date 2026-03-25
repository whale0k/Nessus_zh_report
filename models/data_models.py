#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data models module - Data structures for Nessus Report Generator
"""

from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional


@dataclass
class VulnerabilityInfo:
    """Vulnerability information data structure"""
    plugin_id: str
    cve: str
    risk: str
    host: str
    port: str
    protocol: str
    name: str
    synopsis: str
    description: str
    solution: str
    cvss_v3_score: float = 0.0
    cvss_v2_score: float = 0.0


@dataclass
class HostRiskInfo:
    """Host risk assessment data structure"""
    host: str
    risk_score: float
    risk_level: str
    vulnerabilities: List[VulnerabilityInfo]


@dataclass
class RiskStatistics:
    """Risk statistics container"""
    total_hosts: int = 0
    total_vulnerabilities: int = 0
    critical_hosts: int = 0
    high_hosts: int = 0
    medium_hosts: int = 0
    low_hosts: int = 0
    safe_hosts: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    info_vulnerabilities: int = 0

    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary"""
        return {
            '主机数总计': self.total_hosts,
            '超危主机-数量': self.critical_hosts,
            '高危主机-数量': self.high_hosts,
            '中危主机-数量': self.medium_hosts,
            '低危主机-数量': self.low_hosts,
            '安全主机-数量': self.safe_hosts,
            '漏洞数量总计': self.total_vulnerabilities,
            '超危漏洞-数量': self.critical_vulnerabilities,
            '高危漏洞-数量': self.high_vulnerabilities,
            '中危漏洞-数量': self.medium_vulnerabilities,
            '低危漏洞-数量': self.low_vulnerabilities,
            '信息漏洞-数量': self.info_vulnerabilities,
        }

    def get_percentage(self, count: int, total: int) -> str:
        """Calculate percentage safely"""
        if total == 0:
            return "0.0%"
        return f"{count / total * 100:.1f}%"


@dataclass
class ReportConfig:
    """Report generation configuration"""
    customer_name: str = "目标企业"
    company_name: str = "安全服务公司"
    excel_prefix: str = "漏洞整改表"
    word_prefix: str = "漏洞扫描汇报及修复建议"
    output_dir: str = "./reports/"
    filter_level: str = "high_above"
    generate_excel: bool = True
    generate_word: bool = True
