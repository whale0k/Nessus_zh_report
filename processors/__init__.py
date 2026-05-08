#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Processors module - Data processors for Nessus Report Generator
"""

from .vulnerability import VulnerabilityProcessor, MultiFileProcessor

__all__ = [
    'VulnerabilityProcessor',
    'MultiFileProcessor'
]
