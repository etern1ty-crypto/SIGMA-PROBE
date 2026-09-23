# Что действительно проверено

Проверка от **2026-09-23**, Linux, Python **3.14.7**. Это локальные результаты рабочего дерева, **не hosted CI badge и не production certification**.

## Исполненные проверки

| Проверка | Результат | Доказательство |
|---|---|---|
| Unit/regression/integration/CLI/security/packaging | **138 tests, 0 failures, 0 errors, 0 skips** | [test-results.json](../evidence/test-results.json), [полный вывод](../evidence/test-run.txt) |
| Реальный demo pipeline | 56 событий, 7 IP, 2 high, 1 medium, 4 info, 1 group | [demo-verified.json](../evidence/demo-verified.json), [report.json](../examples/report.json) |
| Исходные дефекты | Восемь targeted воспроизведений; 47 пунктов статического/семантического аудита | [original-reproductions.json](../evidence/original-reproductions.json), [AUDIT.md](AUDIT.md) |
| Offline source install | Fresh venv без system-site-packages; `pip install --no-index .` успешен | [environment.json](../evidence/environment.json) |
| Чистые зависимости | В venv только pip и sigma-probe; pip check успешен | [environment.json](../evidence/environment.json) |
| Outside-source execution | Установленный пакет запускается из /tmp с `python -I` | [environment.json](../evidence/environment.json) |
| Portable zipapp | Реальный analyze под `python -I -S`, без site-packages | [packaging.json](../evidence/packaging.json) |
| Wheel/sdist | Assets, entry point, METADATA/RECORD hashes, version consistency, safe source selection | tests/test_packaging.py |
| Syntax/stdlib imports/local doc links | 42 Python files, 55 local links, zero runtime/build dependencies; ограниченный scope | [repo-check.json](../evidence/repo-check.json) |
| HTML | Просмотрены desktop, mobile expanded, dark, empty и partial states; мобильный перенос заголовков исправлен | [visual-qa.json](../evidence/visual-qa.json) |

`test-results.json` содержит точную длительность последнего запуска и SHA-256 совокупности Python sources. Это fingerprint выполненного кода, а не line-coverage percentage. Coverage tool не запускался; «100% покрытия» не заявляется.

## Какие регрессии защищены

- Combined/Common/JSONL, IPv6, aware timestamps, locale-independent даты, gzip/stdin и input accounting.
- Duplicate/conflicting JSON aliases, invalid UTF-8, oversized строки/распакованный вход, event/actor/pair budgets.
- Trust boundary X-Forwarded-For, explicit host mixing, malformed absolute URL.
- Positive/encoded request payloads и benign PHP/redirect/health отрицательные примеры.
- Real sparse path identity, близость конкретных событий, запрет transitive chaining и deterministic ordering.
- Bounded scoring/repetition, suppression, средние group scores после scoring, повторный запуск без stale state.
- Настоящее применение local IoC, expiry, CIDR/IPv6, literal matching и запрет runtime network через socket mock.
- Query redaction, HMAC actor/group IDs, HTML escaping/CSP, control/bidi output safety.
- Private file modes, atomic bundle rollback, concurrent output bundles, validation до создания staging.
- CLI stdout/stderr/exit 0/2/3/4; SIGINT/SIGTERM на блокирующем stdin, восстановление handlers/logging.
- Закрытие input generator при ранней ошибке downstream; 500 seeded malformed JSON случаев.
- Packaging не захватывает `.venv`/cache и отвергает symlinks в выбранных исходниках.

Socket mock доказывает отсутствие сетевого обращения в проверенном сценарии, а не заменяет независимый egress audit всех возможных будущих изменений. Fuzzer с фиксированным seed — ограниченный regression corpus, не exhaustive fuzzing.

## Synthetic benchmark

[Машинный результат](../evidence/benchmark.json):

| Показатель | Наблюдение |
|---|---:|
| События | 50000 |
| IPv6 actors | 1000 |
| Вход | 4636500 bytes |
| Время analysis + in-memory report projection | 2.8319 s |
| Скорость в этом сценарии | 17655.8 events/s |
| Peak RSS процесса | 71.93 MiB |

Сценарий — periodic health checks, все должны остаться нулевого риска. Создание входа и rendering/write файлов исключены из таймера. Один запуск на текущем sandbox, не capacity SLA; длинные URL, множество совпадений и плотная корреляция могут потреблять значительно больше ресурсов. Это **не precision/recall benchmark** и не сравнение с конкурентами.

Повторить:

```bash
python3 scripts/benchmark.py --events 50000 --actors 1000
```

## Воспроизводимые команды

```bash
python3 scripts/run_tests.py --json-output evidence/test-results.json
python3 scripts/check_repo.py
python3 scripts/build_dist.py
```

Точный трёхкомандный README Quickstart отдельно выполнен в новом venv: установка без index, реальный analyze config.example.toml и получение всех трёх отчётов. После установки также проверены pip check и запуск вне source directory.

## Дополнительная проверка в GitHub Actions

- [PR #6](https://github.com/etern1ty-crypto/SIGMA-PROBE/pull/6): Python 3.11, 3.12 и 3.13, `unittest`, `pytest`, сборка wheel/sdist/zipapp и контейнерный smoke test прошли.
- [Docker lab](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/runs/35845259275): `docker compose config`, Nginx `-t`, синтетический replay через Juice Shop, анализ 15 событий, один high actor и проверка bundle прошли. Workflow теперь также явно проверяет количество событий, high actor и отсутствие невалидных строк.
- [Матрица совместимости](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/runs/35846770795): повторный replay прошёл с Nginx и реальным Angie 1.12.1; zipapp выполнил анализ и проверку bundle внутри официальных контейнеров Astra Linux 1.8, РЕД ОС 8 и ALT Linux p11 без сети и записи в корневую файловую систему. Это проверки конкретных контейнерных образов, не нативных хостов.
- [Внешний тестовый набор AIT-LDS V2.1](EVALUATION.md): 8 516 принятых Apache-запросов, 6 акторов, один основной атакующий актор обнаружен; actor-level recall зависит от политики переноса построчных меток (1/3 либо 1/2). Этого недостаточно для заявления о качестве на production-трафике.

## Что НЕ проверено

- Локальный Docker и нативные установки Angie/Астра/РЕД ОС/ALT Linux на целевых хостах; контейнерные прогоны не подтверждают политики безопасности или сертифицированные редакции хостов.
- Windows/macOS: локально выполнен Python 3.14.7/Linux; CI подтверждает 3.11–3.13 на Ubuntu.
- Ruff, mypy, pip-audit и актуальная база advisories: недоступны без установки/сети. Простая AST-проверка не заменяет эти инструменты.
- Pytest локально не установлен; в CI он выполнил существующий `unittest.TestCase` набор после установки dev requirements.
- Репрезентативные разрешённые клиентские логи, detection accuracy, performance worst case, paid pilots/PMF.
- Независимый pentest/полный security review, проверка OS/container CVE и подтверждение upstream-лицензии.

Zero third-party runtime/build Python dependencies уменьшает поверхность зависимостей, но не исключает проблемы Python/ОС. Production gates остаются обязательными: [PRODUCTION.md](PRODUCTION.md), [LICENSE](../LICENSE).
