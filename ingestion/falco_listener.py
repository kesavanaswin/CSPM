"""
Falco / eBPF Runtime Telemetry Ingestion
-----------------------------------------
LIVE mode: tails Falco's JSON output socket/log for syscall events.
DEMO mode: reads pre-recorded sample_data/falco_events.json.

Output is a per-container time series of syscall frequency vectors, which
feeds directly into ml/anomaly_detector.py for baseline modeling.
"""

import json
import os


class FalcoListener:
    def __init__(self, config):
        self.mode = config["mode"]
        self.log_path = config["ingestion"]["falco"]["log_path"]
        self.socket_path = config["ingestion"]["falco"].get("socket_path")

    def read_events(self):
        if self.mode == "live":
            return self._read_live()
        return self._read_demo()

    def _read_demo(self):
        with open(self.log_path) as f:
            data = json.load(f)
        return data["events"]

    def _read_live(self):
        # Placeholder for real integration: Falco can be configured to write
        # JSON output events to a file/socket via its gRPC output plugin.
        # This reads newline-delimited JSON if the socket has been mounted
        # as a readable log file.
        events = []
        if os.path.exists(self.socket_path):
            with open(self.socket_path) as f:
                for line in f:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return events

    def events_by_container(self):
        """Group syscall frequency vectors by container_id."""
        grouped = {}
        for e in self.read_events():
            cid = e["container_id"]
            grouped.setdefault(cid, []).append(e["syscall_freq"])
        return grouped
