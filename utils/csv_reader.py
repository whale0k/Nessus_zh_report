#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSV reader module - Utilities for reading Nessus CSV files
"""

import csv
import os
import glob
import logging
from typing import List, Dict, Tuple, Any
from collections import defaultdict

from config.constants import AppConstants
from models import VulnerabilityInfo

logger = logging.getLogger(__name__)


class CSVReader:
    """CSV file reader for Nessus vulnerability exports"""

    @staticmethod
    def read_vulnerabilities(csv_file_path: str) -> Tuple[List[VulnerabilityInfo], Dict[str, List[VulnerabilityInfo]]]:
        """Read vulnerabilities from CSV file

        Returns:
            Tuple of (vulnerabilities list, host_vulnerabilities dict)
        """
        vulnerabilities = []
        host_vulnerabilities = defaultdict(list)

        try:
            file_opened = False

            for encoding in AppConstants.CSV_ENCODINGS:
                try:
                    with open(csv_file_path, 'r', encoding=encoding) as file:
                        reader = csv.DictReader(file)
                        logger.info(f"Successfully opened CSV with {encoding} encoding")

                        for row in reader:
                            plugin_id = row.get('Plugin ID', '').strip()
                            risk_level = row.get('Risk', '').strip()

                            if not plugin_id:
                                continue

                            vuln = VulnerabilityInfo(
                                plugin_id=plugin_id,
                                cve=row.get('CVE', ''),
                                risk=risk_level,
                                host=row.get('Host', ''),
                                port=row.get('Port', ''),
                                protocol=row.get('Protocol', ''),
                                name=row.get('Name', ''),
                                synopsis=row.get('Synopsis', ''),
                                description=row.get('Description', ''),
                                solution=row.get('Solution', ''),
                                cvss_v3_score=0.0,
                                cvss_v2_score=0.0
                            )
                            vulnerabilities.append(vuln)
                            host_vulnerabilities[vuln.host].append(vuln)

                        file_opened = True
                        break

                except UnicodeDecodeError:
                    logger.debug(f"Failed to read with {encoding} encoding, trying next...")
                    continue
                except Exception as e:
                    logger.debug(f"Error with {encoding} encoding: {e}")
                    continue

            if not file_opened:
                raise Exception("Unable to read CSV file with any supported encoding")

            logger.info(f"Read {len(vulnerabilities)} vulnerabilities from CSV")
            return vulnerabilities, host_vulnerabilities

        except Exception as e:
            logger.error(f"Error reading CSV file: {e}")
            raise

    @staticmethod
    def find_csv_files(target_dir: str = AppConstants.TARGET_DIR) -> List[str]:
        """Find CSV files in target directory"""
        if not os.path.exists(target_dir):
            logger.warning(f"Target directory '{target_dir}' does not exist. Creating it...")
            os.makedirs(target_dir, exist_ok=True)
            logger.info(f"Created target directory: {target_dir}")
            logger.info("Please place your CSV files in target directory and run script again.")
            return []

        csv_pattern = os.path.join(target_dir, "*.csv")
        csv_files = glob.glob(csv_pattern)

        if not csv_files:
            logger.warning(f"No CSV files found in '{target_dir}' directory.")
            logger.info("Please place your Nessus CSV export files in target directory.")
            return []

        csv_files.sort()
        return csv_files

    @staticmethod
    def get_csv_file_info(csv_file: str) -> Dict[str, Any]:
        """Get CSV file information"""
        filename = os.path.basename(csv_file)
        file_size = os.path.getsize(csv_file) / (1024 * 1024)
        return {
            'path': csv_file,
            'name': filename,
            'size': file_size
        }
