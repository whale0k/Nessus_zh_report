#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main entry point for Nessus Report Generator

This script processes Nessus vulnerability CSV exports or .nessus files and generates:
1. Chinese vulnerability remediation Excel reports
2. Comprehensive vulnerability assessment Word documents
"""

import os
import logging
from datetime import datetime
from typing import List, Tuple

from config import ConfigManager
from config.constants import AppConstants
from services import DatabaseManager, TenableAPIClient
from processors import VulnerabilityProcessor, MultiFileProcessor
from generators import ExcelReportGenerator, WordReportGenerator
from utils import setup_logging, CSVReader, NessusFileReader, UserInterface, StatisticsCalculator


logger = setup_logging()


def find_scan_files() -> Tuple[List[str], List[str]]:
    """Find both CSV and .nessus files in target directory"""
    csv_files = CSVReader.find_csv_files()
    nessus_reader = NessusFileReader()

    nessus_files = []
    target_dir = './target'
    if os.path.exists(target_dir):
        for filename in os.listdir(target_dir):
            if filename.lower().endswith('.nessus'):
                nessus_files.append(os.path.join(target_dir, filename))
        nessus_files.sort()

    return csv_files, nessus_files


def select_files() -> List[str]:
    """Display file selection menu and return selected files"""
    csv_files, nessus_files = find_scan_files()

    total_files = len(csv_files) + len(nessus_files)
    if total_files == 0:
        logger.error("No CSV or .nessus files found. Exiting.")
        return []

    print(f"\n在 './target' 目录下找到 {total_files} 个扫描文件:")
    print("0. 全部文件 - 默认")

    index = 1
    file_options = []

    for file_path in csv_files:
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) / (1024 * 1024)
        print(f"{index}. [CSV] {filename} ({file_size:.1f}MB)")
        file_options.append(('csv', file_path))
        index += 1

    for file_path in nessus_files:
        filename = os.path.basename(file_path)
        file_size = os.path.getsize(file_path) / (1024 * 1024)
        print(f"{index}. [.nessus] {filename} ({file_size:.1f}MB)")
        file_options.append(('nessus', file_path))
        index += 1

    while True:
        try:
            choice = input(f"\n请选择要处理的文件 (0-{total_files}, 默认为0): ").strip()

            if not choice or choice == "0":
                logger.info("选择处理: 全部文件")
                return [f[1] for f in file_options]

            choice_num = int(choice)
            if 1 <= choice_num <= total_files:
                file_type, selected_file = file_options[choice_num - 1]
                filename = os.path.basename(selected_file)
                logger.info(f"选择处理: [{file_type.upper()}] {filename}")
                return [selected_file]
            else:
                print(f"请输入有效的选项 (0-{total_files})")

        except ValueError:
            print("请输入有效的数字")
        except KeyboardInterrupt:
            logger.info("用户取消操作")
            return []


def main():
    """Main function - Complete Nessus report generation workflow"""
    try:
        config_manager = ConfigManager()

        db_manager = DatabaseManager(config_manager.db_path)
        api_client = TenableAPIClient()
        processor = VulnerabilityProcessor(db_manager, api_client, config_manager)
        excel_generator = ExcelReportGenerator()
        word_generator = WordReportGenerator(config_manager.template_path)

        selected_files = select_files()
        if not selected_files:
            logger.info("No files selected. Exiting.")
            return

        filter_level = UserInterface.get_filter_level()
        generate_excel, generate_word = UserInterface.get_format_choice()

        logger.info("Starting Nessus report generation...")

        logger.info("Step 1: Analyzing host risks based on all vulnerabilities...")

        all_vulnerabilities = []
        combined_host_risks = {}

        csv_files = [f for f in selected_files if f.lower().endswith('.csv')]
        nessus_files = [f for f in selected_files if f.lower().endswith('.nessus')]

        for csv_file in csv_files:
            filename = os.path.basename(csv_file)
            logger.info(f"Processing CSV file: {filename}")

            if not os.path.exists(csv_file):
                logger.error(f"CSV file does not exist: {csv_file}")
                continue

            file_vulnerabilities, file_host_risks = processor.process_csv_for_host_analysis(csv_file)

            if file_vulnerabilities:
                all_vulnerabilities.extend(file_vulnerabilities)

                for host, risk_info in file_host_risks.items():
                    if host in combined_host_risks:
                        existing_score = combined_host_risks[host]['risk_score']
                        new_score = risk_info['risk_score']
                        if new_score > existing_score:
                            combined_host_risks[host] = risk_info
                    else:
                        combined_host_risks[host] = risk_info

                logger.info(f"  - Found {len(file_vulnerabilities)} vulnerabilities from {filename}")

        for nessus_file in nessus_files:
            filename = os.path.basename(nessus_file)
            logger.info(f"Processing .nessus file: {filename}")

            if not os.path.exists(nessus_file):
                logger.error(f".nessus file does not exist: {nessus_file}")
                continue

            file_vulnerabilities, file_host_risks = MultiFileProcessor.process_nessus_for_host_analysis(nessus_file)

            if file_vulnerabilities:
                all_vulnerabilities.extend(file_vulnerabilities)

                for host, risk_info in file_host_risks.items():
                    if host in combined_host_risks:
                        existing_score = combined_host_risks[host]['risk_score']
                        new_score = risk_info['risk_score']
                        if new_score > existing_score:
                            combined_host_risks[host] = risk_info
                    else:
                        combined_host_risks[host] = risk_info

                logger.info(f"  - Found {len(file_vulnerabilities)} vulnerabilities from {filename}")

        if not all_vulnerabilities:
            logger.error("No vulnerabilities found in selected file(s)")
            return

        host_risks = combined_host_risks
        total_hosts = len(host_risks)

        if len(selected_files) == 1:
            filename = os.path.basename(selected_files[0])
            logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities across {total_hosts} hosts in {filename}")
        else:
            processed_files = [os.path.basename(f) for f in selected_files]
            logger.info(f"Combined results from {len(selected_files)} files: {', '.join(processed_files)}")
            logger.info(f"Total: {len(all_vulnerabilities)} vulnerabilities across {total_hosts} hosts")

        logger.info(f"Step 2: Filtering and translating vulnerabilities (filter: {filter_level})...")
        vulnerabilities = processor.process_filtered_vulnerabilities(all_vulnerabilities, filter_level)

        logger.info(f"Successfully processed {len(vulnerabilities)} vulnerabilities for reports")

        output_dir = config_manager.output_dir
        os.makedirs(output_dir, exist_ok=True)

        current_date = datetime.now().strftime("%Y%m%d")

        if len(selected_files) == 1:
            file_suffix = f"({current_date})"
        else:
            file_suffix = f"_合并报告({current_date})"

        excel_file = None
        if generate_excel:
            logger.info("Generating Excel reports...")
            excel_file = os.path.join(
                output_dir,
                f"{config_manager.excel_prefix}{file_suffix}.xlsx"
            )
            excel_generator.create_remediation_report(vulnerabilities, excel_file, "all")

        risk_counts = StatisticsCalculator.calculate_risk_counts(all_vulnerabilities)
        host_risk_counts = StatisticsCalculator.calculate_host_risk_counts(host_risks)

        UserInterface.print_statistics(all_vulnerabilities, host_risks, risk_counts, host_risk_counts)

        word_file = None
        if generate_word:
            logger.info("Generating Word report...")
            word_config = {
                "客户名称": config_manager.customer_name,
                "实施公司": config_manager.company_name
            }

            word_file = os.path.join(
                output_dir,
                f"{config_manager.word_prefix}"
                f"{file_suffix.replace(current_date, datetime.now().strftime('%Y_%m'))}.docx"
            )

            word_generator.create_vulnerability_report(
                vulnerabilities,
                word_config,
                word_file,
                filter_level,
                risk_counts,
                host_risk_counts,
                total_hosts
            )

        UserInterface.print_summary(excel_file, word_file)

    except Exception as e:
        logger.error(f"Application error: {e}")
        raise


if __name__ == "__main__":
    main()
