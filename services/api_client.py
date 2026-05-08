#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API client module - Tenable API client for fetching Chinese vulnerability data
"""

import re
import requests
import logging
from typing import Optional, Dict

from config.constants import AppConstants

logger = logging.getLogger(__name__)


class TenableAPIClient:
    """Tenable API client for fetching Chinese vulnerability data"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': AppConstants.USER_AGENT})
        self._build_id_cn: Optional[str] = None
        self._build_id_tw: Optional[str] = None

    def _get_build_id(self, base_url: str) -> Optional[str]:
        """Fetch dynamic buildId from Tenable website"""
        try:
            logger.info(f"Fetching buildId from {base_url}")
            response = self.session.get(
                f"{base_url}/zh-CN/plugins",
                timeout=AppConstants.API_TIMEOUT
            )
            response.raise_for_status()

            content = response.text
            match = re.search(r'"buildId":"([^"]+)"', content)
            if match:
                build_id = match.group(1)
                logger.info(f"Successfully fetched buildId: {build_id}")
                return build_id
            else:
                logger.warning(f"Could not find buildId in response from {base_url}")
                return None
        except Exception as e:
            logger.error(f"Failed to fetch buildId from {base_url}: {e}")
            return None

    def _get_api_url_cn(self) -> Optional[str]:
        """Get Chinese API URL (dynamically built)"""
        if self._build_id_cn is None:
            self._build_id_cn = self._get_build_id(AppConstants.TENABLE_BASE_URL_CN)
        if self._build_id_cn:
            return f"{AppConstants.TENABLE_BASE_URL_CN}{AppConstants.TENABLE_API_PATH.format(build_id=self._build_id_cn)}"
        return None

    def _get_api_url_tw(self) -> Optional[str]:
        """Get Traditional Chinese API URL (dynamically built)"""
        if self._build_id_tw is None:
            self._build_id_tw = self._get_build_id(AppConstants.TENABLE_BASE_URL_TW)
        if self._build_id_tw:
            return f"{AppConstants.TENABLE_BASE_URL_TW}{AppConstants.TENABLE_API_PATH_TW.format(build_id=self._build_id_tw)}"
        return None

    @staticmethod
    def convert_traditional_to_simplified(text: str) -> str:
        """Convert Traditional Chinese to Simplified Chinese using mapping table"""
        if not text:
            return text

        result = text
        for trad, simp in AppConstants.TRADITIONAL_TO_SIMPLIFIED.items():
            result = result.replace(trad, simp)
        return result

    def fetch_plugin_info(self, plugin_id: str) -> Optional[Dict]:
        """Fetch Chinese plugin information from Tenable API"""
        params = {
            'q': f'script_id:({plugin_id})',
            'sort': '',
            'page': '1'
        }

        api_url_cn = self._get_api_url_cn()
        if api_url_cn:
            try:
                logger.info(f"Fetching plugin info from CN API for ID: {plugin_id}")
                response = self.session.get(
                    api_url_cn,
                    params=params,
                    timeout=AppConstants.API_TIMEOUT
                )
                response.raise_for_status()

                data = response.json()
                plugins = data.get('pageProps', {}).get('plugins', [])

                if plugins:
                    plugin_data = plugins[0]['_source']
                    logger.info(f"Successfully fetched CN data for plugin {plugin_id}")
                    return plugin_data
                else:
                    logger.warning(f"No data found in CN API for plugin {plugin_id}")

            except Exception as e:
                logger.warning(f"CN API request failed for plugin {plugin_id}: {e}")
                self._build_id_cn = None

        api_url_tw = self._get_api_url_tw()
        if api_url_tw:
            try:
                logger.info(f"Fetching plugin info from TW API (backup) for ID: {plugin_id}")
                response = self.session.get(
                    api_url_tw,
                    params=params,
                    timeout=AppConstants.API_TIMEOUT
                )
                response.raise_for_status()

                data = response.json()
                plugins = data.get('pageProps', {}).get('plugins', [])

                if plugins:
                    plugin_data = plugins[0]['_source']
                    plugin_data = self._convert_plugin_data(plugin_data)
                    logger.info(f"Successfully fetched and converted TW data for plugin {plugin_id}")
                    return plugin_data
                else:
                    logger.warning(f"No data found in TW API for plugin {plugin_id}")

            except Exception as e:
                logger.error(f"TW API request failed for plugin {plugin_id}: {e}")
                self._build_id_tw = None

        return None

    def _convert_plugin_data(self, plugin_data: Dict) -> Dict:
        """Convert Traditional Chinese to Simplified Chinese in plugin data"""
        if not isinstance(plugin_data, dict):
            return plugin_data

        converted = {}
        for key, value in plugin_data.items():
            if isinstance(value, str):
                converted[key] = self.convert_traditional_to_simplified(value)
            elif isinstance(value, dict):
                converted[key] = self._convert_plugin_data(value)
            else:
                converted[key] = value
        return converted
