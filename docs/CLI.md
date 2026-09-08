# API / CLI справочник

## Вызовы

```text
sigma-probe --help
sigma-probe --version
sigma-probe validate-config [--config FILE]
sigma-probe analyze [OPTIONS]
```

Эквивалентные entrypoints:

```bash
python3 -m sigma_probe analyze --input access.log
python3 -m sigma_probe.main analyze --input access.log
python3 dist/sigma-probe.pyz analyze --input access.log
```

Module invocation требует установленного пакета либо `PYTHONPATH=src`; zipapp автономен и не требует site-packages. Сохранён legacy spelling `python3 -m sigma_probe.main --input access.log --config config.example.toml`, который маршрутизируется в `analyze`. Новые контракты v3 не имитируют неработавшие YAML/модель v2.

## `analyze`

| Флаг | Аргумент | Назначение |
|---|---|---|
| `-c`, `--config` | TOML file | Проверенный конфиг |
| `-i`, `--input` | file / `.gz` / `-` | Повторяемый флаг; один сайт, конечная выгрузка |
| `-o`, `--output` | directory | Родитель отдельного report bundle |
| `--input-format` | auto/nginx/apache/combined/common/json/jsonl | Формат входа, не отчёта |
| `--format` | json/html/text | Повторяемый формат отчёта |
| `--site` | string | Метка одного сайта в отчёте |
| `--since` | ISO 8601 с timezone | Inclusive начало |
| `--until` | ISO 8601 с timezone | Exclusive конец |
| `--strict` | без аргумента | Первая malformed строка — fatal error |
| `--max-events` | int | Число принятых событий до отказа |
| `--max-input-bytes` | int | Общие распакованные байты до отказа |
| `--allowlist` | IP/CIDR | Повторяемый explicit suppression |
| `--anonymize-ips` / `--no-anonymize-ips` | без аргумента | Override privacy setting |
| `--include-query` / `--no-include-query` | без аргумента | Override query disclosure; default false |
| `--fail-on` | none/low/medium/high | Triage threshold для кода 3 |
| `--log-level` | DEBUG/INFO/WARNING/ERROR | Уровень stderr logs |
| `--json-logs` | без аргумента | JSONL logging в stderr |
| `--debug` | без аргумента | DEBUG logging и traceback при ошибке |

Нет `--workers`, background mode, API listener, remote feed URL, auto-block или response action. Неизвестные параметры не игнорируются.

## Примеры

```bash
# Локальная запись, один сайт
sigma-probe analyze -i /srv/snapshots/client-a/access.log --site client-a -o reports/client-a

# Несколько непересекающихся ротаций; gzip распаковывается внутри
sigma-probe analyze -i access.log.1 -i access.log.2.gz --format json --format html

# Конечный stdin stream; cat должен завершиться
cat examples/access.jsonl | sigma-probe analyze -i - --input-format jsonl --strict

# Исключить проверенный адрес сканера, сохранив evidence
sigma-probe analyze -i access.log --allowlist 192.0.2.10/32 --fail-on high

# Приватный клиентский отчёт с ephemeral IP pseudonyms
sigma-probe analyze -i access.log --site client-a --anonymize-ips --no-include-query
```

`--allowlist` — не защита от атак и не автоматическое trust-discovery. Адреса в примерах принадлежат documentation ranges. Не копируйте синтетические IoC в настоящую систему блокировок.

## Коды возврата

| Код | Значение | Запись отчётов |
|---|---|---|
| `0` | Валидный полный вход обработан, fail-on не сработал | Да; validate-config пишет только stdout |
| `1` | Непредвиденная внутренняя ошибка или закрытый stdout | Не гарантирована; см. stderr |
| `2` | CLI/config/input/I/O/resource-budget ошибка | Новый частичный bundle не публикуется; старые не трогаются |
| `3` | Есть неподавленный actor на/выше `--fail-on` | Да, до возврата кода |
| `4` | Malformed записи пропущены в допустимом ratio | Да, помечены partial; имеет приоритет над кодом 3 |
| `130` | SIGINT / KeyboardInterrupt | Незавершённый staging очищается |
| `143` | SIGTERM | Незавершённый staging очищается |

Код 0 не означает «угроз нет», если `--fail-on=none`, и никогда не означает «взломов не было». Пустой вход — явная zero-event сводка, не доказательство безопасности. Код 4 нельзя трактовать как полное покрытие.

После атомарного commit сигнал или ошибка directory fsync/stdout могут случиться до acknowledgement. В таком случае может существовать **полный** report bundle при ненулевом exit code. Проверьте каталог, а не перезапускайте job слепо. SIGKILL/сбой питания не позволяют выполнить cleanup.

## stdout и stderr

`analyze` возвращает в stdout один JSON object:

```json
{
  "exit_code": 0,
  "input_status": "complete",
  "reports": {
    "json": "/reports/RUN_DIRECTORY/report.json",
    "html": "/reports/RUN_DIRECTORY/report.html",
    "text": "/reports/RUN_DIRECTORY/report.txt"
  },
  "summary": {
    "accepted_events": 56,
    "actors": 7,
    "high": 2,
    "medium": 1,
    "low": 0,
    "info": 4,
    "suppressed": 0,
    "correlation_groups": 1,
    "invalid_lines": 0,
    "filtered_events": 0
  }
}
```

Здесь `RUN_DIRECTORY` — иллюстрация автоматически сгенерированного имени, не буквальный путь установки. Фактические paths извлекайте из stdout. Структура самого отчёта описана в [REPORT_SCHEMA.md](REPORT_SCHEMA.md).

Логи — stderr. `--json-logs` добавляет timestamp, level, logger, message. По умолчанию ошибки malformed строки не раскрывают её содержимое. `--debug` предназначен для доверенной диагностики, stderr также нужно проверять перед отправкой.

## Python API

```python
from sigma_probe.config import Settings, PrivacyConfig, ReportingConfig
from sigma_probe.main import AnalysisPipeline

settings = Settings(
    site="client-a",
    privacy=PrivacyConfig(anonymize_ips=True, include_query=False),
    reporting=ReportingConfig(output_dir="reports/client-a"),
)

result = AnalysisPipeline(settings).run("examples/access.log")
print(result.report["summary"])
print(result.report_paths["html"])
```

Без filesystem delivery:

```python
from sigma_probe.config import Settings
from sigma_probe.main import AnalysisPipeline

pipeline = AnalysisPipeline(Settings())
result = pipeline.run(["examples/access.log"], write_reports=False)
assert result.report_paths == {}
assert result.report["summary"]["accepted_events"] == 56
```

API принимает строку или последовательность строк input paths; `None` использует `config.input.files`. В `stdin=` можно передать binary stream при input `-`. `AnalysisPipeline(Settings(...), hmac_key=...)` позволяет явно внедрить секрет; CLI берёт его из environment. Сам Python API с готовым Settings не читает HMAC key из environment автоматически.

**Privacy boundary:** `result.report` уже прошёл privacy projection. `result.actors` содержит исходные IP/URL и не должен отправляться во внешнюю систему без отдельного решения. `write_reports=False` не делает raw API result безопасным.

Ожидаемые ошибки API наследуются от `SigmaProbeError`; `LimitExceeded` — его подкласс. API не превращает их в process exit code и не устанавливает signal handlers. CLI — отдельная граница для process behavior.

## Не является HTTP API

Нет listen port, endpoint, аутентификации HTTP или webhook. Для включения в сервис самостоятельно проектируйте authentication, tenant isolation, storage, job limits и аудит доступа; не публикуйте CLI как произвольный remote path reader.
