#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Database service module - SQLite database manager for caching vulnerability translations
"""

import sqlite3
import logging
from typing import Optional, Dict

from config.constants import AppConstants

logger = logging.getLogger(__name__)


class DatabaseManager:
    """SQLite database manager for caching vulnerability translations"""

    def __init__(self, db_path: str = AppConstants.DEFAULT_DB_PATH):
        self.db_path = db_path
        self.init_database()

    def init_database(self) -> None:
        """Initialize database schema"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS plugins (
                        script_id TEXT PRIMARY KEY,
                        script_name TEXT,
                        script_family TEXT,
                        synopsis TEXT,
                        description TEXT,
                        solution TEXT,
                        risk_factor TEXT,
                        severity TEXT,
                        cvss_v2_score REAL,
                        cvss_v3_score REAL,
                        cvss_v4_score REAL,
                        cvss_v2_severity TEXT,
                        cvss_v3_severity TEXT,
                        cvss_v4_severity TEXT,
                        vpr_score TEXT,
                        vpr_risk_factor TEXT,
                        vpr_severity TEXT,
                        cisa_known_exploited_date TEXT,
                        plugin_type TEXT,
                        sensor TEXT,
                        plugin_publication_date TEXT,
                        plugin_modification_date TEXT,
                        plugin_references TEXT,
                        xrefs TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()
                logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise

    def get_plugin_info(self, plugin_id: str) -> Optional[Dict]:
        """Retrieve plugin information from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(
                    "SELECT * FROM plugins WHERE script_id = ?", (plugin_id,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Error retrieving plugin {plugin_id}: {e}")
            return None

    def save_plugin_info(self, plugin_data: Dict) -> None:
        """Save plugin information to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                def safe_get(data, key, default=""):
                    return data.get(key, default)

                cvss_data = plugin_data.get('cvss', {})

                conn.execute("""
                    INSERT OR REPLACE INTO plugins (
                        script_id, script_name, script_family, synopsis, description,
                        solution, risk_factor, severity, cvss_v2_score, cvss_v3_score,
                        cvss_v4_score, cvss_v2_severity, cvss_v3_severity, cvss_v4_severity,
                        plugin_type, sensor, plugin_publication_date, plugin_modification_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    safe_get(plugin_data, 'script_id'),
                    safe_get(plugin_data, 'script_name'),
                    safe_get(plugin_data, 'script_family'),
                    safe_get(plugin_data, 'synopsis'),
                    safe_get(plugin_data, 'description'),
                    safe_get(plugin_data, 'solution'),
                    safe_get(plugin_data, 'risk_factor'),
                    safe_get(plugin_data, 'severity'),
                    safe_get(cvss_data, 'cvssv2_score', 0.0),
                    safe_get(cvss_data, 'cvssv3_score', 0.0),
                    safe_get(cvss_data, 'cvssv4_score', 0.0),
                    safe_get(cvss_data, 'cvssv2_severity'),
                    safe_get(cvss_data, 'cvssv3_severity'),
                    safe_get(cvss_data, 'cvssv4_severity'),
                    safe_get(plugin_data, 'plugin_type'),
                    safe_get(plugin_data, 'sensor'),
                    safe_get(plugin_data, 'plugin_publication_date'),
                    safe_get(plugin_data, 'plugin_modification_date')
                ))
                conn.commit()
                logger.info(f"Plugin {plugin_data.get('script_id')} saved to database")
        except Exception as e:
            logger.error(f"Error saving plugin data: {e}")
