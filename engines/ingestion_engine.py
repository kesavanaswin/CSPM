"""
engines/ingestion_engine.py
----------------------------
Layer 1: INGESTION ENGINE

Responsible for pulling in the three raw data sources that feed the
rest of the pipeline:

    1. Container static configuration (docker inspect / K8s manifest state)
    2. Vulnerability scan results (Trivy/Grype-like API simulation)
    3. Runtime telemetry events (eBPF / Falco-like event stream)

In a production system these would be live API calls / socket streams.
Here they are simulated by reading JSON fixtures and replaying them
through a generator with a small delay, using a background thread and
a Queue so downstream engines can consume events "as they arrive" --
demonstrating the streaming architecture without needing a real
container runtime.
"""

import json
import os
import queue
import threading
import time
from typing import List, Dict, Generator

from storage.json_store import JSONStore
from utils.logger import get_logger
from utils.models import ContainerConfig, VulnScanResult, VulnFinding, RuntimeEvent

logger = get_logger("engines.ingestion")


class IngestionEngine:
    def __init__(self, containers_path: str, vuln_path: str, runtime_path: str):
        self.containers_path = containers_path
        self.vuln_path = vuln_path
        self.runtime_path = runtime_path

    # ------------------------------------------------------------------
    # Batch loaders (config state + vuln scans are point-in-time snapshots)
    # ------------------------------------------------------------------
    def load_container_configs(self) -> List[ContainerConfig]:
        raw = JSONStore.load(self.containers_path)
        configs = []
        for item in raw:
            try:
                configs.append(ContainerConfig(**item))
            except TypeError as e:
                logger.warning(f"Skipping malformed container record {item.get('container_id', '?')}: {e}")
        logger.info(f"Ingested {len(configs)} container configuration(s).")
        return configs

    def load_vuln_scans(self) -> Dict[str, VulnScanResult]:
        raw = JSONStore.load(self.vuln_path)
        results: Dict[str, VulnScanResult] = {}
        for item in raw:
            try:
                findings = [VulnFinding(**f) for f in item.get("findings", [])]
                result = VulnScanResult(
                    container_id=item["container_id"],
                    image=item["image"],
                    findings=findings,
                    scanned_at=item.get("scanned_at", ""),
                )
                results[result.container_id] = result
            except (KeyError, TypeError) as e:
                logger.warning(f"Skipping malformed vuln scan record: {e}")
        logger.info(f"Ingested vulnerability scans for {len(results)} container(s).")
        return results

    # ------------------------------------------------------------------
    # Streaming loader (runtime telemetry is naturally an event stream)
    # ------------------------------------------------------------------
    def stream_runtime_events(
        self,
        delay: float = 0.0,
        follow: bool = False,
        poll_interval: float = 0.25,
        max_wait: float = None,
    ) -> Generator[RuntimeEvent, None, None]:
        """
        Yield RuntimeEvent objects from the runtime telemetry source.

        By default this replays the static JSON fixture once. When ``follow=True``
it reads any existing events first, then tails the file and emits newly
        appended events in near real time, which matches the behavior of a live
        eBPF/Falco pipeline.
        """
        if not os.path.exists(self.runtime_path):
            logger.warning(f"Runtime events file not found: {self.runtime_path}")
            return

        def _parse_event(raw_line: str):
            line = raw_line.strip()
            if not line:
                return None
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                logger.warning(f"Skipping malformed runtime event line: {raw_line.strip()}")
                return None
            try:
                return RuntimeEvent(**item)
            except TypeError as e:
                logger.warning(f"Skipping malformed runtime event payload: {e}")
                return None

        if not follow:
            raw = JSONStore.load(self.runtime_path)
            logger.info(f"Starting runtime telemetry stream ({len(raw)} events)...")
            for item in raw:
                event = _parse_event(json.dumps(item))
                if event is None:
                    continue
                if delay:
                    time.sleep(delay)
                yield event
            logger.info("Runtime telemetry stream complete.")
            return

        logger.info(f"Tailing runtime telemetry log: {self.runtime_path}")
        with open(self.runtime_path, "r", encoding="utf-8") as handle:
            # Read the current file first so a live simulation starts with the
            # existing events before waiting for new appends.
            for raw_line in handle:
                event = _parse_event(raw_line)
                if event is not None:
                    if delay:
                        time.sleep(delay)
                    yield event

            started_at = time.monotonic()
            while True:
                line = handle.readline()
                if line:
                    event = _parse_event(line)
                    if event is not None:
                        if delay:
                            time.sleep(delay)
                        yield event
                    continue

                if max_wait is not None and (time.monotonic() - started_at) >= max_wait:
                    break
                time.sleep(poll_interval)

    def stream_runtime_events_threaded(self, delay: float = 0.0, follow: bool = False) -> "queue.Queue":
        """
        Runs the runtime event stream on a background thread and pushes
        events onto a thread-safe Queue, demonstrating how a real
        eBPF/Falco collector would feed the Analysis Engine asynchronously
        without blocking the main pipeline. A None sentinel marks the end
        of the stream.
        """
        event_queue: "queue.Queue" = queue.Queue()

        def _producer():
            try:
                for event in self.stream_runtime_events(delay=delay, follow=follow, poll_interval=0.25):
                    event_queue.put(event)
            except Exception as exc:  # pragma: no cover
                logger.exception(f"Runtime event stream failed: {exc}")
            event_queue.put(None)

        thread = threading.Thread(target=_producer, daemon=True, name="RuntimeEventProducer")
        thread.start()
        return event_queue
