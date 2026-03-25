#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Statistics module - Statistical calculations for vulnerability and host risks
"""

from typing import Dict, List, Tuple, Any
from collections import defaultdict, Counter

from config.constants import AppConstants
from models import VulnerabilityInfo, RiskStatistics


class RiskCalculator:
    """Calculate host risk based on vulnerabilities"""

    @staticmethod
    def calculate_host_risk_from_levels(risk_levels: List[str]) -> Tuple[float, str]:
        """Calculate host risk based on vulnerability risk levels (simplified version)"""
        if not risk_levels:
            return 0, "安全"

        level_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0, 'None': 0}
        for level in risk_levels:
            if level in level_count:
                level_count[level] += 1
            else:
                level_count['Info'] += 1

        if level_count['Critical'] > 0:
            risk_score = 100
            risk_level = "超危"
        elif level_count['High'] > 0:
            risk_score = min(85 + level_count['High'] * 3, 99)
            risk_level = "高危"
        elif level_count['Medium'] > 0:
            risk_score = min(60 + level_count['Medium'] * 2, 84)
            risk_level = "中危"
        elif level_count['Low'] > 0:
            risk_score = min(30 + level_count['Low'], 59)
            risk_level = "低危"
        else:
            risk_score = 0
            risk_level = "安全"

        return risk_score, risk_level

    @staticmethod
    def calculate_host_risk(vulnerabilities: List[float]) -> Tuple[float, str]:
        """Calculate host risk based on CVSS scores"""
        if not vulnerabilities:
            return 0, "安全"

        level_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for cvss_score in vulnerabilities:
            if cvss_score >= 9.0:
                level_count['CRITICAL'] += 1
            elif cvss_score >= 7.0:
                level_count['HIGH'] += 1
            elif cvss_score >= 4.0:
                level_count['MEDIUM'] += 1
            elif cvss_score > 0:
                level_count['LOW'] += 1

        base_score = 0

        if level_count['CRITICAL'] > 0:
            base_score = 100
        elif level_count['HIGH'] > 0:
            base_score = min(90 + level_count['HIGH'] * 3, 99)
            high_scores = [s for s in vulnerabilities if 7.0 <= s < 9.0]
            if high_scores:
                avg_high = sum(high_scores) / len(high_scores)
                base_score += (avg_high - 7.0) * 2
        else:
            medium_weight = level_count['MEDIUM'] * 1.5
            low_weight = level_count['LOW'] * 0.5
            base_score = min(medium_weight + low_weight, 70)
            total_vulns = len(vulnerabilities)
            if total_vulns > 10:
                base_score *= 1.2

        density_bonus = RiskCalculator.calculate_density_bonus(level_count)
        final_score = min(base_score + density_bonus, 100)

        return final_score, RiskCalculator.get_risk_level(final_score)

    @staticmethod
    def calculate_density_bonus(level_count: Dict[str, int]) -> float:
        """Calculate vulnerability density bonus"""
        bonus = 0

        for level, count in level_count.items():
            if count >= 5:
                if level == 'CRITICAL':
                    bonus += 20
                elif level == 'HIGH':
                    bonus += 15
                elif level == 'MEDIUM':
                    bonus += 10
                elif level == 'LOW':
                    bonus += 5

        return min(bonus, 30)

    @staticmethod
    def get_risk_level(score: float) -> str:
        """Determine risk level based on score"""
        if score >= 95:
            return "超危"
        elif score >= 80:
            return "高危"
        elif score >= 60:
            return "中危"
        elif score >= 30:
            return "低危"
        else:
            return "安全"


class StatisticsCalculator:
    """Calculate vulnerability and host statistics"""

    @staticmethod
    def calculate_risk_counts(vulnerabilities: List[VulnerabilityInfo]) -> Dict[str, int]:
        """Count vulnerabilities by risk level"""
        risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for vuln in vulnerabilities:
            risk_level = vuln.risk
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
            else:
                risk_counts["Info"] += 1
        return risk_counts

    @staticmethod
    def calculate_host_risk_counts(host_risks: Dict[str, Any]) -> Dict[str, int]:
        """Count hosts by risk level"""
        host_risk_counts = {"超危": 0, "高危": 0, "中危": 0, "低危": 0, "安全": 0}
        for host_info in host_risks.values():
            host_risk_counts[host_info['risk_level']] += 1
        return host_risk_counts

    @staticmethod
    def calculate_comprehensive_stats(
        vulnerabilities: List[VulnerabilityInfo],
        host_risks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate comprehensive statistics"""
        risk_counts = StatisticsCalculator.calculate_risk_counts(vulnerabilities)
        host_risk_counts = StatisticsCalculator.calculate_host_risk_counts(host_risks)

        total_vulns = len(vulnerabilities)
        total_hosts = len(host_risks)

        def safe_percentage(count, total):
            return f"{count/total*100:.1f}%" if total > 0 else "0.0%"

        stats = {
            "主机数总计": total_hosts,
            "超危主机-数量": host_risk_counts.get("超危", 0),
            "超危主机-占比": safe_percentage(host_risk_counts.get("超危", 0), total_hosts),
            "高危主机-数量": host_risk_counts.get("高危", 0),
            "高危主机-占比": safe_percentage(host_risk_counts.get("高危", 0), total_hosts),
            "中危主机-数量": host_risk_counts.get("中危", 0),
            "中危主机-占比": safe_percentage(host_risk_counts.get("中危", 0), total_hosts),
            "低危主机-数量": host_risk_counts.get("低危", 0),
            "低危主机-占比": safe_percentage(host_risk_counts.get("低危", 0), total_hosts),
            "安全主机-数量": host_risk_counts.get("安全", 0),
            "安全主机-占比": safe_percentage(host_risk_counts.get("安全", 0), total_hosts),
            "中危以上主机-占比": safe_percentage(
                host_risk_counts.get("超危", 0) + host_risk_counts.get("高危", 0) +
                host_risk_counts.get("中危", 0),
                total_hosts
            ),
            "漏洞数量总计": total_vulns,
            "超危漏洞-数量": risk_counts.get("Critical", 0),
            "超危漏洞-占比": safe_percentage(risk_counts.get("Critical", 0), total_vulns),
            "高危漏洞-数量": risk_counts.get("High", 0),
            "高危漏洞-占比": safe_percentage(risk_counts.get("High", 0), total_vulns),
            "中危漏洞-数量": risk_counts.get("Medium", 0),
            "中危漏洞-占比": safe_percentage(risk_counts.get("Medium", 0), total_vulns),
            "低危漏洞-数量": risk_counts.get("Low", 0),
            "低危漏洞-占比": safe_percentage(risk_counts.get("Low", 0), total_vulns),
            "信息漏洞-数量": risk_counts.get("Info", 0),
            "信息漏洞-占比": safe_percentage(risk_counts.get("Info", 0), total_vulns),
        }

        return stats

    @staticmethod
    def group_vulnerabilities_by_risk(
        vulnerabilities: List[VulnerabilityInfo]
    ) -> Dict[str, List[VulnerabilityInfo]]:
        """Group vulnerabilities by risk level"""
        grouped = defaultdict(list)
        for vuln in vulnerabilities:
            risk_level = StatisticsCalculator.normalize_risk_level(vuln.risk)
            grouped[risk_level].append(vuln)
        return dict(grouped)

    @staticmethod
    def normalize_risk_level(risk: str) -> str:
        """Normalize risk level string"""
        risk_mapping = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Info": "Info",
            "None": "Info"
        }
        return risk_mapping.get(risk, "Info")
