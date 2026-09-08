# Changelog

## 3.0.0rc1 — 2026-09-08

Ревизия предоставленного SIGMA-PROBE / Helios архива; не заявлена как официальный upstream release.

### Product

Offline log triage и клиентские evidence-first отчёты для MSP/DevOps/агентств. Убраны неподтверждённые обещания live/FFT/ML/confirmed-botnet/automatic blocking.

### Реализовано

- CLI analyze/validate-config/version, gzip/stdin, multiple files, time filters и meaningful exit codes.
- Strict TOML/dataclasses, zero runtime/build Python dependencies.
- IPv6/UTC/JSON aliases/trusted proxy boundary, запрет разных явных JSON hosts.
- Reviewed local IoC с expiry/size/entries limits, exact CIDR и hashes.
- Additive 0–100 scoring, корректные group means, human-review playbooks.
- Query omission, HMAC IP/group pseudonyms, safe printable output.
- Атомарные приватные JSON/HTML/TXT bundles; responsive/dark HTML без JS/CDN.
- Реальные unit/regression/E2E/CLI/security/packaging tests без skip.
- Offline wheel/sdist/zipapp, Docker/Compose/CI config и полная документация.

### Исправлено

Несовместимые pipeline/model/CLI contracts; нулевые/повторно пересчитываемые metrics; tags/scoring ordering; vectors без path identity; transitive и временно ложная correlation; HTML injection; неработающие IoC/recommendations; import-time log side effect; stale state; report cleanup и error paths.

### Breaking changes

YAML → TOML, Pydantic/scientific/Poetry → stdlib, новые API/report contracts, honest CV вместо FFT, local вместо remote feeds. [MIGRATION.md](docs/MIGRATION.md).

### Gates

Upstream license не подтверждён; реальный precision/recall, hosted CI, Docker и актуальная advisory-проверка Python/OS образа не выполнены в этом sandbox. [VALIDATION.md](docs/VALIDATION.md) отделяет доказанное от непроверенного.
