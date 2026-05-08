#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
User interface module - User interaction utilities
"""

import os
import logging
from typing import List, Dict, Any, Tuple

from config.constants import AppConstants
from models import VulnerabilityInfo

logger = logging.getLogger(__name__)


class UserInterface:
    """User interaction utilities"""

    @staticmethod
    def select_files(file_list: List[str], file_type: str = 'file') -> List[str]:
        """Display file selection menu and return selected files"""
        print(f"\n在 './target' 目录下找到 {len(file_list)} 个{file_type}文件:")
        print("0. 全部文件 - 默认")

        for i, file_path in enumerate(file_list, 1):
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path) / (1024 * 1024)
            print(f"{i}. {filename} ({file_size:.1f}MB)")

        while True:
            try:
                choice = input(f"\n请选择要处理的{file_type}文件 (0-{len(file_list)}, 默认为0): ").strip()

                if not choice or choice == "0":
                    logger.info(f"选择处理: 全部{file_type}文件")
                    return file_list

                choice_num = int(choice)
                if 1 <= choice_num <= len(file_list):
                    selected_file = file_list[choice_num - 1]
                    filename = os.path.basename(selected_file)
                    logger.info(f"选择处理: {filename}")
                    return [selected_file]
                else:
                    print(f"请输入有效的选项 (0-{len(file_list)})")

            except ValueError:
                print("请输入有效的数字")
            except KeyboardInterrupt:
                logger.info("用户取消操作")
                return []

    @staticmethod
    def select_csv_files(csv_files: List[str]) -> List[str]:
        """Display CSV file selection menu and return selected files"""
        return UserInterface.select_files(csv_files, 'CSV')

    @staticmethod
    def get_filter_level() -> str:
        """Get user's vulnerability filter level choice"""
        print("\n选择漏洞输出等级:")
        print("0. 高危及以上漏洞 (仅Critical和High) - 默认")
        print("1. 全部漏洞")
        filter_choice = input("请选择 (0-1, 默认为0): ").strip()

        if not filter_choice or filter_choice == "0":
            logger.info("选择输出: 高危及以上漏洞")
            return "high_above"
        else:
            logger.info("选择输出: 全部漏洞")
            return "all"

    @staticmethod
    def get_format_choice() -> Tuple[bool, bool]:
        """Get user's report format choice"""
        print("\n选择生成报告格式:")
        print("0. 全部格式 (Excel + Word) - 默认")
        print("1. Excel报告")
        print("2. Word报告")
        format_choice = input("请选择 (0-2, 默认为0): ").strip()

        if not format_choice or format_choice == "0":
            logger.info("选择生成: 全部格式 (Excel + Word)")
            return True, True
        elif format_choice == "1":
            logger.info("选择生成: Excel报告")
            return True, False
        elif format_choice == "2":
            logger.info("选择生成: Word报告")
            return False, True
        else:
            logger.info("选择生成: 全部格式 (Excel + Word)")
            return True, True

    @staticmethod
    def print_statistics(
        vulnerabilities: List[VulnerabilityInfo],
        host_risks: Dict[str, Any],
        risk_counts: Dict[str, int],
        host_risk_counts: Dict[str, int]
    ) -> None:
        """Print vulnerability and host statistics"""
        logger.info("\n=== 漏洞统计汇总 ===")

        total_vulns = len(vulnerabilities)
        total_hosts = len(host_risks)

        logger.info(f"漏洞统计:")
        logger.info(f"  超危漏洞: {risk_counts.get('Critical', 0)} ({risk_counts.get('Critical', 0)/total_vulns*100:.1f}%)")
        logger.info(f"  高危漏洞: {risk_counts.get('High', 0)} ({risk_counts.get('High', 0)/total_vulns*100:.1f}%)")
        logger.info(f"  中危漏洞: {risk_counts.get('Medium', 0)} ({risk_counts.get('Medium', 0)/total_vulns*100:.1f}%)")
        logger.info(f"  低危漏洞: {risk_counts.get('Low', 0)} ({risk_counts.get('Low', 0)/total_vulns*100:.1f}%)")
        logger.info(f"  信息漏洞: {risk_counts.get('Info', 0)} ({risk_counts.get('Info', 0)/total_vulns*100:.1f}%)")
        logger.info(f"  漏洞总计: {total_vulns}")

        logger.info(f"\n主机统计:")
        logger.info(f"  超危主机: {host_risk_counts.get('超危', 0)} ({host_risk_counts.get('超危', 0)/total_hosts*100:.1f}%)")
        logger.info(f"  高危主机: {host_risk_counts.get('高危', 0)} ({host_risk_counts.get('高危', 0)/total_hosts*100:.1f}%)")
        logger.info(f"  中危主机: {host_risk_counts.get('中危', 0)} ({host_risk_counts.get('中危', 0)/total_hosts*100:.1f}%)")
        logger.info(f"  低危主机: {host_risk_counts.get('低危', 0)} ({host_risk_counts.get('低危', 0)/total_hosts*100:.1f}%)")
        logger.info(f"  安全主机: {host_risk_counts.get('安全', 0)} ({host_risk_counts.get('安全', 0)/total_hosts*100:.1f}%)")
        logger.info(f"  主机总计: {total_hosts}")

    @staticmethod
    def print_summary(excel_file: str = None, word_file: str = None) -> None:
        """Print report generation summary"""
        logger.info("\n=== 报告生成完成 ===")
        if excel_file:
            logger.info(f"Excel整改表: {excel_file}")
        if word_file:
            logger.info(f"Word评估报告: {word_file}")

        generated_reports = []
        if excel_file:
            generated_reports.append("Excel报告")
        if word_file:
            generated_reports.append("Word报告")

        if generated_reports:
            logger.info(f"已生成: {', '.join(generated_reports)}")
        else:
            logger.info("未生成任何报告")
