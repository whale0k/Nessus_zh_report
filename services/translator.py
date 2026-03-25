#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Translation service module - Provides translation service with multiple sources
"""

import re
import requests
import logging
from typing import List

from config.constants import AppConstants

logger = logging.getLogger(__name__)


class TranslationService:
    """Translation service supporting multiple sources as fallback"""

    def __init__(self, translation_sources: List[str] = None):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': AppConstants.USER_AGENT})
        self.translation_sources = translation_sources or ['bing', 'google']
        logger.info(f"Translation sources priority: {self.translation_sources}")

        self.bing_base_url = "https://cn.bing.com/translator"
        self.bing_api_url = "https://cn.bing.com/ttranslatev3"
        self.bing_key = None
        self.bing_token = None
        self.bing_ig = None
        self.bing_iid = "translator.5028"

        self.google_api_url = "https://translate.googleapis.com/translate_a/single"

    def _get_bing_params(self) -> bool:
        """Fetch Bing translation dynamic parameters (Key, Token, IG)"""
        try:
            logger.info("Fetching parameters from Bing Translator...")
            response = self.session.get(self.bing_base_url, timeout=10)
            response.raise_for_status()
            content = response.text

            match = re.search(r'var params_AbusePreventionHelper\s*=\s*\[(\d+),\s*"([^"]+)",\s*(\d+)\]', content)
            if match:
                self.bing_key = match.group(1)
                self.bing_token = match.group(2)
            else:
                logger.warning("Could not find params_AbusePreventionHelper in Bing page")
                return False

            match_ig = re.search(r'IG:"([^"]+)"', content)
            if match_ig:
                self.bing_ig = match_ig.group(1)
            else:
                logger.warning("Could not find IG in Bing page")
                return False

            match_iid = re.search(r'data-iid="([^"]+)"', content)
            if match_iid:
                self.bing_iid = match_iid.group(1)

            return True
        except Exception as e:
            logger.error(f"Error fetching Bing parameters: {e}")
            return False

    def _translate_with_bing(self, text: str, target_lang: str) -> str:
        """Translate using Bing Translator"""
        if not self.bing_key or not self.bing_token:
            if not self._get_bing_params():
                raise Exception("Failed to initialize Bing params")

        url = f"{self.bing_api_url}?isVertical=1&&IG={self.bing_ig}&IID={self.bing_iid}.1"

        data = {
            'fromLang': 'auto-detect',
            'text': text,
            'to': target_lang,
            'token': self.bing_token,
            'key': self.bing_key
        }

        try:
            response = self.session.post(url, data=data, timeout=10)
            response.raise_for_status()
            result = response.json()

            if result and isinstance(result, list) and len(result) > 0:
                translations = result[0].get('translations', [])
                if translations:
                    return translations[0].get('text', text)
            return text
        except Exception as e:
            logger.info(f"Bing translation failed ({e}), refreshing parameters and retrying...")
            if self._get_bing_params():
                url = f"{self.bing_api_url}?isVertical=1&&IG={self.bing_ig}&IID={self.bing_iid}.2"
                data['token'] = self.bing_token
                data['key'] = self.bing_key

                response = self.session.post(url, data=data, timeout=10)
                result = response.json()
                if result and isinstance(result, list) and len(result) > 0:
                    translations = result[0].get('translations', [])
                    if translations:
                        return translations[0].get('text', text)
            raise e

    def _translate_with_google(self, text: str, target_lang: str) -> str:
        """Translate using Google Translate (Web interface)"""
        params = {
            "client": "gtx",
            "sl": "auto",
            "tl": 'zh-CN' if target_lang == 'zh-Hans' else target_lang,
            "dt": "t",
            "q": text
        }

        try:
            response = self.session.get(self.google_api_url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            translated_text = ""
            if data and isinstance(data, list) and len(data) > 0:
                for item in data[0]:
                    if item and isinstance(item, list) and len(item) > 0:
                        translated_text += item[0]

            return translated_text if translated_text else text

        except Exception as e:
            raise Exception(f"Google Translation failed: {e}")

    def translate(self, text: str, target_lang: str = 'zh-Hans') -> str:
        """Translate text, trying configured translation sources in order"""
        if not text:
            return ""

        if len(text) > 3000:
            logger.warning(f"Text too long for translation ({len(text)} chars), truncating...")
            text = text[:3000]

        for source in self.translation_sources:
            try:
                if source.lower() == 'bing':
                    return self._translate_with_bing(text, target_lang)
                elif source.lower() == 'google':
                    return self._translate_with_google(text, target_lang)
            except Exception as e:
                logger.warning(f"{source} translation failed: {e}")
                continue

        logger.error("All translation methods failed.")
        return text
