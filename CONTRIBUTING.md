# Contributing to SIGMA-PROBE

Сначала прочитайте [лицензионный статус](LICENSE). Публичная дистрибуция требует подтверждения upstream прав; это не заявленный официальный upstream release.

## Локальная проверка

Python 3.11+, никаких сторонних пакетов:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t . -v
python3 scripts/check_repo.py
python3 scripts/build_dist.py
```

Машинный протокол: `python3 scripts/run_tests.py --json-output evidence/test-results.json`. Synthetic baseline: `python3 scripts/benchmark.py --events 50000 --actors 1000`.

## Правила изменений

- Reproducer до исправления; никаких tautologies или скрытых skip.
- Для нового правила: positive, encoded и benign negative cases.
- Не выдавать heuristic cadence/correlation за confirmed botnet, attribution или exploit success.
- Config keys: строгая валидация, ranges/defaults, CLI/env precedence и документация.
- Любое пользовательское поле проходит общую privacy projection и HTML escaping.
- Внешние данные/корреляция ограничены явными budgets; не скрывайте truncation.
- Не добавлять runtime network/remote feed/update без отдельного security/product решения.
- Сохранять exact IP/CIDR, UTC, health/PHP/redirect/NAT negative controls.
- Не добавлять зависимости ради единичной stdlib-операции.

## Архитектура

[ARCHITECTURE.md](docs/ARCHITECTURE.md) описывает стадии и порядок. Concrete analysis stage реализует process(context) и включается явно; ingestion/enrichment/profiling имеют собственные stream/event interfaces. Нет no-op базового detector или dynamic class loading из пользовательского config.

Enrichment и IoC — до profiling; correlation/meta — до scoring. Новый тег требует синхронизации весов, validation, evidence, документации и тестов. ATT&CK/recommendations добавляются только при содержательном основании.

## Review checklist

- [ ] Tests без failures/errors/skips; match counts и score contributions сходятся.
- [ ] Empty/malformed/oversize, failures, signals и cleanup проверены.
- [ ] Нет raw query/IP leakage в privacy-safe report.
- [ ] Wheel/zipapp запускаются без site-packages; версии совпадают.
- [ ] README/local links актуальны, badges и benchmarks честные.
- [ ] HTML просмотрен при 1200px/390px, dark/expanded/empty/partial.
- [ ] Для dependencies рассмотрены license, advisories, resolution и необходимость.

check_repo.py — structural checker, не mypy/ruff/security scanner. Ruff config — optional; локальный Ruff run не заявлен. Production gates — в [PRODUCTION.md](docs/PRODUCTION.md).

Для security report используйте synthetic fixture, не реальные клиентские логи/секреты. См. [SECURITY.md](SECURITY.md).
