#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generators module - Report generators for Nessus Report Generator
"""

from .excel import ExcelReportGenerator
from .word import WordReportGenerator

__all__ = [
    'ExcelReportGenerator',
    'WordReportGenerator'
]
