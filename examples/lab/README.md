# Local incident lab

This lab sends synthetic requests only to a Juice Shop container behind a local Nginx proxy. The proxy is exposed only on `127.0.0.1:18080`; the lab network is internal. The analyzer runs afterwards with no network connection. HTTP 200 does **not** prove exploitation.

From the repository root, with Docker Compose available:

```bash
mkdir -p examples/lab/reports
LAB_UID="$(id -u)" LAB_GID="$(id -g)" docker compose -f examples/lab/compose.yml up -d proxy
docker compose -f examples/lab/compose.yml --profile traffic run --rm traffic
LAB_UID="$(id -u)" LAB_GID="$(id -g)" docker compose -f examples/lab/compose.yml --profile analyze run --rm analyzer
```

Read the generated bundle under `examples/lab/reports/`, then verify it with `PYTHONPATH=src python3 -m sigma_probe verify-report examples/lab/reports/<run-id>`. The traffic generator waits briefly for the proxy and sends normal requests and suspicious path/query patterns. Live server timestamps vary; the existing `examples/access.log` is the deterministic replay fixture.

The images are version-tagged, not digest-pinned. A [manual GitHub Actions workflow](../../.github/workflows/lab.yml) checks Compose, validates Nginx, sends traffic and verifies the output bundle when dispatched. Before a public reproducibility claim, record and pin image digests and execute the lab on the target platform. Docker is unavailable in this workspace, so the workflow has not yet been observed here.

Stop lab containers with:

```bash
docker compose -f examples/lab/compose.yml --profile traffic --profile analyze down
```

The named log volume and locally generated reports are preserved. Remove only lab-owned data after reviewing it.
