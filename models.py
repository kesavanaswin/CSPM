"""
Lightweight SQLite persistence layer.
No ORM used on purpose, to keep the framework dependency-light.
"""

import sqlite3
import json
import time
from contextlib import contextmanager

from config import DB_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS containers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    image TEXT NOT NULL,
    exposure TEXT DEFAULT 'internal',
    privilege TEXT DEFAULT 'non_root',
    first_seen REAL,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS config_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id INTEGER,
    rule TEXT,
    message TEXT,
    severity TEXT,
    created_at REAL,
    FOREIGN KEY(container_id) REFERENCES containers(id)
);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id INTEGER,
    cve_id TEXT,
    package TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    severity TEXT,
    created_at REAL,
    FOREIGN KEY(container_id) REFERENCES containers(id)
);

CREATE TABLE IF NOT EXISTS runtime_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id INTEGER,
    rule TEXT,
    priority TEXT,
    output TEXT,
    is_anomaly INTEGER DEFAULT 0,
    created_at REAL,
    FOREIGN KEY(container_id) REFERENCES containers(id)
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id INTEGER,
    vulnerability_score REAL,
    exposure_score REAL,
    privilege_score REAL,
    total_score REAL,
    severity_label TEXT,
    created_at REAL,
    FOREIGN KEY(container_id) REFERENCES containers(id)
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def upsert_container(name, namespace, image, exposure="internal", privilege="non_root"):
    now = time.time()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM containers WHERE name=? AND namespace=?",
            (name, namespace),
        ).fetchone()
        if row:
            conn.execute(
                """UPDATE containers SET image=?, exposure=?, privilege=?, last_seen=?
                   WHERE id=?""",
                (image, exposure, privilege, now, row["id"]),
            )
            return row["id"]
        cur = conn.execute(
            """INSERT INTO containers (name, namespace, image, exposure, privilege,
               first_seen, last_seen) VALUES (?,?,?,?,?,?,?)""",
            (name, namespace, image, exposure, privilege, now, now),
        )
        return cur.lastrowid


def add_config_finding(container_id, rule, message, severity):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO config_findings (container_id, rule, message, severity, created_at)
               VALUES (?,?,?,?,?)""",
            (container_id, rule, message, severity, time.time()),
        )


def add_vuln_finding(container_id, cve_id, package, installed_version, fixed_version, severity):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO vuln_findings
               (container_id, cve_id, package, installed_version, fixed_version, severity, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (container_id, cve_id, package, installed_version, fixed_version, severity, time.time()),
        )


def add_runtime_event(container_id, rule, priority, output, is_anomaly=0):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO runtime_events (container_id, rule, priority, output, is_anomaly, created_at)
               VALUES (?,?,?,?,?,?)""",
            (container_id, rule, priority, output, int(is_anomaly), time.time()),
        )


def add_risk_score(container_id, vuln_score, exposure_score, privilege_score, total_score, severity_label):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO risk_scores
               (container_id, vulnerability_score, exposure_score, privilege_score,
                total_score, severity_label, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (container_id, vuln_score, exposure_score, privilege_score,
             total_score, severity_label, time.time()),
        )


def get_dashboard_data():
    """Return each container with its latest risk score and finding counts."""
    with get_conn() as conn:
        containers = conn.execute("SELECT * FROM containers").fetchall()
        results = []
        for c in containers:
            latest_risk = conn.execute(
                """SELECT * FROM risk_scores WHERE container_id=?
                   ORDER BY created_at DESC LIMIT 1""",
                (c["id"],),
            ).fetchone()
            vuln_count = conn.execute(
                "SELECT COUNT(*) as n FROM vuln_findings WHERE container_id=?", (c["id"],)
            ).fetchone()["n"]
            config_count = conn.execute(
                "SELECT COUNT(*) as n FROM config_findings WHERE container_id=?", (c["id"],)
            ).fetchone()["n"]
            anomaly_count = conn.execute(
                "SELECT COUNT(*) as n FROM runtime_events WHERE container_id=? AND is_anomaly=1",
                (c["id"],),
            ).fetchone()["n"]
            results.append({
                "container": dict(c),
                "risk": dict(latest_risk) if latest_risk else None,
                "vuln_count": vuln_count,
                "config_count": config_count,
                "anomaly_count": anomaly_count,
            })
        # Highest risk first
        results.sort(key=lambda r: (r["risk"]["total_score"] if r["risk"] else 0), reverse=True)
        return results
