#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Logger module - Logging configuration for Nessus Report Generator
"""

import logging
from typing import Optional

from config.constants import AppConstants


def setup_logging(log_file: Optional[str] = None) -> logging.Logger:
    """Configure logging with file and console handlers"""
    if log_file is None:
        log_file = AppConstants.DEFAULT_LOG_FILE

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name"""
    return logging.getLogger(name)
