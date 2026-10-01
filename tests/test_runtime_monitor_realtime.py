import json
import threading
import time

from runtime_monitor import read_events


def test_read_events_follows_new_lines(tmp_path):
    log_path = tmp_path / "falco_events.jsonl"
    log_path.write_text("", encoding="utf-8")

    def producer():
        time.sleep(0.05)
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps({
                    "rule": "Custom rule",
                    "priority": "Warning",
                    "output_fields": {"container.name": "demo-app"},
                    "output": "Suspicious write detected",
                }) + "\n"
            )
            handle.flush()

    thread = threading.Thread(target=producer, daemon=True)
    thread.start()

    events = read_events(str(log_path), follow=True, poll_interval=0.01, max_wait=0.5)
    event = next(events)

    assert event["rule"] == "Custom rule"
    assert event["output_fields"]["container.name"] == "demo-app"
