# SIGMA-PROBE

English · [Русский](README.md)

SIGMA-PROBE turns a finite Nginx/Angie or Apache access-log snapshot into a local investigation report. It prioritizes suspicious actors, links findings to source lines, and suggests checks for an operator. The core uses Python 3.11+ standard library only; a `.pyz` still requires Python. It does not prove compromise or automatically block traffic.

## Try it from a clean checkout

```bash
PYTHONPATH=src python3 -m sigma_probe analyze \
  --input examples/access.log \
  --output reports/demo \
  --site demo-site \
  --anonymize-ips
```

The command prints paths to an HTML dashboard, JSON, text report, and `manifest.json`. Open the HTML locally. Run `PYTHONPATH=src python3 -m sigma_probe verify-report reports/demo/<run-id>` to check the published files.

If you set a separate `SIGMA_PROBE_REPORT_KEY` of at least 32 UTF-8 bytes during both analysis and verification, the manifest also has an HMAC. Without that key, hashes detect accidental damage but do not authenticate origin. IP pseudonymization uses a different key, `SIGMA_PROBE_HMAC_KEY`; it is enabled in the command above but is off by default. Query strings are hidden by default, while URL paths may still contain sensitive information.

An [Angie/Nginx JSONL logging example](examples/angie-nginx-log-format.conf) and [local Juice Shop lab](examples/lab/README.md) are available. The lab passed its synthetic Nginx replay in [GitHub Actions](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/runs/35845259275); Docker is unavailable in this local workspace. See [format compatibility](docs/COMPATIBILITY.md), [architecture](docs/ARCHITECTURE.md), [report schema](docs/REPORT_SCHEMA.md), [production limits](docs/PRODUCTION.md), and [validation notes](docs/VALIDATION.md).

For reviewed exact-IP responses, `propose-block` can print Nginx or iptables rules and rollback text from a report bundle. It never applies the rules; expiry is metadata and must be enforced by the operator's workflow.

## Current boundaries

The default budget is 100,000 events, and profiling retains events in memory. The existing synthetic 50,000-event benchmark is not a production-capacity claim. ATT&CK mappings express context, not attribution or proof of successful exploitation. Detection quality needs labeled real-world evaluation.

The upstream distribution license is **not yet verified**. [LICENSE](LICENSE) and [NOTICE](NOTICE) describe the current status; do not infer MIT redistribution rights from older README text.
