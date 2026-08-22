import re


def metric(compose, service: str, name: str, labels=None) -> float:
    # Scrape :9090/metrics inside the network via the runner container.
    # We exec into the service and curl its own metrics endpoint.
    try:
        out = compose.exec(service, "curl", "-fsS", "http://localhost:9090/metrics", timeout=10)
    except Exception:
        try:
            out = compose.exec(service, "wget", "-qO-", "http://localhost:9090/metrics", timeout=10)
        except Exception:
            return 0.0
    # Parse Prometheus text format: name{label="value",...} value
    # or name value
    total = 0.0
    for line in out.splitlines():
        if not line.startswith(name):
            continue
        # Check labels
        if labels:
            ok = True
            for k, v in labels.items():
                if f'{k}="{v}"' not in line and f"{k}='{v}'" not in line:
                    ok = False
                    break
            if not ok:
                continue
        # Value is last token
        try:
            val = float(line.split()[-1])
            total += val
        except Exception:
            continue
    return total
