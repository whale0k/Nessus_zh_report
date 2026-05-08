#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nessus file reader - Parse .nessus XML format files
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
import logging
from models import VulnerabilityInfo

logger = logging.getLogger(__name__)


class NessusFileReader:
    """Parse Nessus .nessus XML export files"""

    SEVERITY_TO_RISK = {
        '0': 'None',
        '1': 'Low',
        '2': 'Medium',
        '3': 'Critical'
    }

    def __init__(self):
        self.namespaces = {
            '': 'NessusClientData_v2'
        }

    def read_file(self, file_path: str) -> List[VulnerabilityInfo]:
        """Read and parse .nessus file"""
        logger.info(f"Reading .nessus file: {file_path}")

        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            vulnerabilities = []
            report_hosts = root.findall('.//ReportHost')

            logger.info(f"Found {len(report_hosts)} hosts in .nessus file")

            for report_host in report_hosts:
                host_name = report_host.get('name', 'Unknown')
                host_properties = self._parse_host_properties(report_host)

                host_ip = host_properties.get('host-ip', host_name)

                report_items = report_host.findall('ReportItem')
                for report_item in report_items:
                    vuln = self._parse_report_item(report_item, host_ip, host_name)
                    if vuln:
                        vulnerabilities.append(vuln)

            logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from .nessus file")
            return vulnerabilities

        except ET.ParseError as e:
            logger.error(f"Failed to parse .nessus file: {e}")
            raise ValueError(f"Invalid .nessus XML format: {e}")
        except Exception as e:
            logger.error(f"Error reading .nessus file: {e}")
            raise

    def _parse_host_properties(self, report_host) -> Dict[str, str]:
        """Extract host properties from ReportHost"""
        properties = {}
        host_properties = report_host.find('HostProperties')

        if host_properties is not None:
            for tag in host_properties.findall('tag'):
                name = tag.get('name')
                value = tag.text or ''
                properties[name] = value

        return properties

    def _parse_report_item(self, report_item, host_ip: str, host_name: str) -> Optional[VulnerabilityInfo]:
        """Parse a single ReportItem into VulnerabilityInfo"""
        try:
            plugin_id = report_item.get('pluginID')
            if not plugin_id:
                return None

            plugin_name = report_item.get('pluginName', '')
            port = report_item.get('port', '0')
            protocol = report_item.get('protocol', '')

            risk_factor = report_item.find('risk_factor')
            risk = risk_factor.text if risk_factor is not None else 'None'

            severity = report_item.get('severity', '0')
            if risk == 'None' and severity in self.SEVERITY_TO_RISK:
                risk = self.SEVERITY_TO_RISK[severity]

            cvss_v3_score = report_item.find('cvss3_base_score')
            cvss_v2_score = report_item.find('cvss_base_score')

            cvss3 = None
            if cvss_v3_score is not None and cvss_v3_score.text:
                try:
                    cvss3 = float(cvss_v3_score.text)
                except ValueError:
                    pass

            cvss2 = None
            if cvss_v2_score is not None and cvss_v2_score.text:
                try:
                    cvss2 = float(cvss_v2_score.text)
                except ValueError:
                    pass

            description_elem = report_item.find('description')
            description = description_elem.text if description_elem is not None else ''

            solution_elem = report_item.find('solution')
            solution = solution_elem.text if solution_elem is not None else ''

            synopsis_elem = report_item.find('synopsis')
            synopsis = synopsis_elem.text if synopsis_elem is not None else ''

            if description and synopsis and synopsis not in description:
                description = f"{synopsis}\n\n{description}"

            cve_elem = report_item.find('cve')
            cve = cve_elem.text if cve_elem is not None else None

            plugin_output_elem = report_item.find('plugin_output')
            plugin_output = plugin_output_elem.text if plugin_output_elem is not None else ''

            return VulnerabilityInfo(
                plugin_id=int(plugin_id),
                cve=cve,
                risk=risk,
                host=host_ip,
                port=port,
                protocol=protocol,
                name=plugin_name,
                synopsis=synopsis,
                description=description or '',
                solution=solution or '',
                cvss_v3_score=cvss3,
                cvss_v2_score=cvss2
            )

        except Exception as e:
            logger.warning(f"Error parsing ReportItem for host {host_ip}: {e}")
            return None

    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get basic information about .nessus file"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            report_hosts = root.findall('.//ReportHost')
            total_vulnerabilities = 0

            for report_host in report_hosts:
                items = report_host.findall('ReportItem')
                total_vulnerabilities += len(items)

            return {
                'total_hosts': len(report_hosts),
                'total_vulnerabilities': total_vulnerabilities,
                'file_path': file_path
            }

        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            return {
                'total_hosts': 0,
                'total_vulnerabilities': 0,
                'file_path': file_path,
                'error': str(e)
            }
