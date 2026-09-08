# Формат JSON-отчёта

`schema_version`: **1.0**. [Полный валидный пример](../examples/report.json). CLI stdout — отдельный envelope со сводкой и filenames, не сам report.

JSON создаётся явной сериализацией, без произвольного default=str и без NaN/Infinity. Sets превращаются в sorted arrays. Время — aware ISO 8601 UTC.

## Верхний уровень

| Поле | Тип | Содержание |
|---|---|---|
| schema_version | string | 1.0 |
| metadata | object | tool, version, site, generated_at, elapsed_seconds, config_sha256, input_status, privacy, limitations |
| summary | object | Сводка всех принятых событий/акторов |
| inputs | array | Источники, content hashes, accounting |
| parse_errors | array | До 20 input ID/line/reason samples без raw lines |
| detectors | object | behavior, temporal, correlation, meta, scoring, ioc statistics |
| actors | array | Все профили; score DESC, canonical IP ASC |
| campaigns | array | Эвристические группы сходства |
| recommendations | array | Human-review playbooks |

`elapsed_seconds` измеряет анализ до файлового rendering/write, не полную CLI latency. Config hash — SHA-256 канонического фактически использованного Settings JSON, включая runtime input override, но не HMAC key. Для воспроизведения сохраните также версию, сам config и snapshots.

`input_status` — complete либо partial. Privacy: `query_included`, `ip_pseudonymization`, `key_mode` (not_applicable / ephemeral_per_run / operator_key).

## Summary и инварианты

Поля: accepted_events, actors, high, medium, low, info, suppressed, correlation_groups, invalid_lines, filtered_events. Severity counts учитывают только неподавленных actors.

```text
actors = high + medium + low + info + suppressed
accepted_events = sum(actor.metrics.requests)
source.lines = source.blank + source.invalid + source.filtered + source.accepted
```

Пустой или полностью отфильтрованный валидный вход сам по себе не partial. Partial означает допустимый пропуск malformed записей. Фатально превышенный budget/ratio не производит новый частичный report bundle.

## Inputs

`input_id`, `name`, `sha256`, `bytes_read`, `lines`, `blank`, `invalid`, `filtered`, `accepted`. Name — basename или `<stdin>`, не абсолютный path. Input-N соответствует порядку входа и evidence references.

SHA-256 считается по распакованным байтам, включая исходные переводы строк, blank/malformed строки. Для gzip это не хеш compressed файла. Повтор физического файла через hardlink/path отвергается; overlapping content разных файлов автоматически не дедуплицируется.

## Actors

| Поле | Контракт |
|---|---|
| ip_address | Canonical IP либо HMAC pseudonym с префиксом ip- |
| score | Integer 0..100 |
| severity | info/low/medium/high по настроенным порогам |
| suppressed | Boolean; evidence сохраняется |
| tags | Sorted string array |
| score_breakdown | Tag/bonus/cap_adjustment → integer; сумма равна score |
| metrics | requests, unique_paths, response_bytes, error_ratio, avg_url_entropy, first_seen, last_seen |
| behavior | Вычисленные cadence metrics, если хватает данных |
| evidence | Все собранные records, не raw event dump |
| mitre_techniques | Context references с id/name/tactic/url/status=context_only |

Unique paths не учитывает query; URL entropy сама по себе не риск. Timestamps first/last могут быть null у вручную созданных пустых API profiles; ingestion создаёт только непустые профили.

## Evidence

`source`, `kind`, `details`, `confidence`, `metrics`, `references`. Confidence 0..1 — heuristic, не калиброванная вероятность; confidence 1.0 у scoring относится к вычислению формулы, а не успеху атаки.

References: input_id, 1-based line, timestamp, method, URL после privacy projection, status_code, ioc_feeds (совпавшие имена snapshots). Полный match count остаётся в metrics; request examples ограничены sample_events, behavior/temporal — максимум тремя. JSON включает все собранные evidence, но не все события.

По умолчанию query/fragment скрыты; при include-query могут попасть credentials/tokens/PII. Raw path также может быть чувствительным.

## Campaigns и рекомендации

Group: id, type=correlated_activity, mean_score, actors, tags, mitre_techniques. Mean score вычислен после scoring. ID детерминирован по участникам, не уникален для истории инцидентов; различайте runs по site/time/input hashes. При privacy group ID тоже псевдонимизируется. Сходство не должно автоматически превращаться в blocklist.

Recommendation: id, priority, title, actor_ids, action_items, rationale. Priority — максимальный среди соответствующих actors; IDs прошли ту же privacy projection. Все действия — текст для аналитика, ни одно не выполнено автоматически.

## Совместимость

Интегрируйтесь по именованным полям JSON и проверяйте schema_version. Не парсите HTML/text и не полагайтесь на постоянные generated_at, elapsed, run directory или ephemeral pseudonyms. Fixed-key псевдонимы стабильны при том же ключе/ID; разные клиенты должны использовать раздельные ключи.

Determinism tests сравнивают смысловые actors/groups/recommendations/detectors при разных PYTHONHASHSEED, а не байтовое совпадение всех метаданных разных запусков.
