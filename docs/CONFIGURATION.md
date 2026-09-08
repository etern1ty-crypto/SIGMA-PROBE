# Настройка и конфигурация

Полный пример: [config.example.toml](../config.example.toml). Проверка без анализа и создания отчётов:

```bash
sigma-probe validate-config --config config.example.toml
```

## Правила загрузки

Приоритет: **встроенные defaults < TOML < поддерживаемые переменные окружения < явные CLI-флаги**.

- Конфигурация — UTF-8 TOML, максимум 64 KiB. YAML 2.x больше не принимается.
- Неизвестные поля, duplicate TOML keys, неверные типы, NaN/Infinity, неправильные диапазоны, повторяющиеся inputs/formats отклоняются.
- Файл конфигурации сначала валидируется целиком: CLI override не скрывает ошибку в неизвестном параметре.
- Пути, явно записанные в TOML, разрешаются относительно его папки. Пути из CLI/env — относительно cwd.
- Если `reporting.output_dir` отсутствует в TOML, встроенный `reports` относится к cwd.
- `-` зарезервирован для stdin. Один stdin, несколько отдельных обычных/`.gz` файлов; нет встроенного glob expansion.
- `.env.example` — инструкция оператору. Приложение **не читает .env автоматически**.

## Верхний уровень

| Поле | Тип / default | Правило |
|---|---|---|
| `schema_version` | int, `1` | Другие версии отвергаются |
| `site` | string, `local-site` | 1..120 печатных символов; метка отчёта, не автоматический фильтр доменов |
| `log_level` | string, `INFO` | DEBUG / INFO / WARNING / ERROR |
| `allowlist_cidrs` | string array, `[]` | До 1000 явных IPv4/IPv6 CIDR; одиночный IP допустим |

Allowlist сохраняет события/теги, но выставляет score 0, исключает actor из корреляции и рекомендаций. CIDR нормализуются с `strict=False`: `192.0.2.17/24` означает всю `192.0.2.0/24`. Поэтому **всегда проверяйте итоговый диапазон**. Для одного адреса используйте IP без `/24` либо `/32`/`/128`.

## `[input]`

| Поле | Default | Значение |
|---|---|---|
| `files` | `[]` | До 100 файлов; без CLI/config input запуск не выполняется |
| `format` | `auto` | auto, nginx, apache, combined, common, json, jsonl |
| `invalid_policy` | `skip` | `error` останавливает на первой некорректной записи |
| `max_error_ratio` | `0.05` | 0..1; invalid / nonblank по всем прочитанным источникам |
| `since` | отсутствует | Inclusive ISO 8601 с timezone |
| `until` | отсутствует | Exclusive ISO 8601 с timezone, строго позже since |
| `trusted_proxy_cidrs` | `[]` | До 100 сетей доверенных proxy; по умолчанию XFF игнорируется |

`auto` выбирает JSON по первому непробельному `{` **для каждой строки**, иначе Common/Combined. Nginx/Apache/Combined принимают базовый Combined или Common без дополнительных полей. `common` требует отсутствие referrer/agent хвоста. Произвольные custom log_format нужно предварительно преобразовать в поддерживаемый JSONL.

Полностью невалидный непустой вход всегда ошибка, даже при `max_error_ratio=1`. Пустой или полностью отфильтрованный валидный вход формирует явный zero-event отчёт. Malformed строки не записываются целиком в ошибки: только input ID, line, reason, первые 20 примеров ошибок. При допустимых пропусках report partial, CLI exit 4.

### JSONL

Каноническая запись:

```json
{"timestamp":"2026-09-08T00:00:00Z","source_ip":"203.0.113.10","method":"GET","url":"/catalog?page=1","status_code":200,"response_size":512,"user_agent":"Mozilla/5.0","host":"shop.example.test"}
```

| Каноническое поле | Допустимые aliases | Обязательность |
|---|---|---|
| `timestamp` | `time_iso8601` | Обязательно; ISO with offset или finite Unix seconds |
| `source_ip` | `remote_addr` | Обязательно; адрес peer до возможного XFF resolution |
| `method` | `request_method`, `http_method` | Обязательно |
| `url` | `request_uri`, `url_raw` | Обязательно; origin-form, absolute HTTP(S), `*` |
| `status_code` | `status` | Обязательно; int или строка цифр, 100..599 |
| `response_size` | `body_bytes_sent` | Default 0; `-` = 0 |
| `user_agent` | `http_user_agent` | Необязательно; отсутствующее/null = пустая строка |
| `http_x_forwarded_for` | `x_forwarded_for` | Необязательно; используется только при доверенном peer |
| `host` | нет | Необязательно; разные явно заданные hosts в одном запуске запрещены |

Значения одновременно переданных aliases должны совпадать. Остальные поля не экспортируются и не исполняются. URL ограничен 16 384 символами, User-Agent — 4096; HTTP method — валидный token до 32 символов. Сырые C0/C1 controls и surrogate code points в основных строковых полях запрещены. Encoded payloads анализируются после ограниченного декодирования и безопасно отображаются.

Если строка содержит `"-"` вместо request line, она считается malformed, а не вымышленным GET-событием. Тела POST/PUT, cookies и ответы сервера access-log обычно не содержит; их анализ не поддерживается.

### Рекомендуемый Nginx JSON format

Следующий пример — конфигурация веб-сервера, её нужно проверить и применить отдельно по вашей процедуре изменений; SIGMA-PROBE не меняет сервер:

```nginx
log_format sigma_json escape=json
  '{"time_iso8601":"$time_iso8601",'
  '"remote_addr":"$remote_addr",'
  '"request_method":"$request_method",'
  '"request_uri":"$request_uri",'
  '"status":$status,'
  '"body_bytes_sent":$body_bytes_sent,'
  '"http_user_agent":"$http_user_agent",'
  '"http_x_forwarded_for":"$http_x_forwarded_for",'
  '"host":"$host"}';
access_log /var/log/nginx/sigma-access.jsonl sigma_json;
```

Для нескольких vhost разделяйте файлы/выгрузки по сайтам. Если Nginx уже корректно применяет real_ip и `$remote_addr` содержит настоящий клиентский IP, обычно не нужно повторно доверять XFF в анализаторе.

## `[limits]`

| Поле | Default | Допустимый диапазон |
|---|---|---|
| `max_events` | 100000 | 1..10000000 принятых событий |
| `max_actors` | 10000 | 1..100000 IP |
| `max_input_bytes` | 268435456 | 1..10737418240 распакованных байтов суммарно |
| `max_line_bytes` | 65536 | 64..1048576 байтов, включая перевод строки |
| `max_candidate_pairs` | 100000 | 1..10000000 уникальных пар |
| `max_pair_evaluations` | 1000000 | 1..100000000 единиц candidate/time/vector/grouping работы |

Любое превышение означает **отказ с кодом 2 без нового report bundle**, а не отчёт по тихо обрезанной выборке. Существующие отчёты не удаляются. Не повышайте все лимиты одновременно: память зависит от длины URL, распределения IP и числа совпадений, не только количества строк.

## `[detection]`

| Поле | Default | Смысл / диапазон |
|---|---|---|
| `temporal_min_events` | 10 | 3..100000 событий для cadence |
| `temporal_cv` | 0.15 | 0..1; low variance, не FFT |
| `enumeration_min_paths` | 10 | 2..100000 разных error paths |
| `enumeration_error_ratio` | 0.7 | 0..1; минимальная доля 4xx/5xx |
| `burst_window_seconds` | 300 | 1..86400; закрытое sliding window |
| `auth_failure_threshold` | 10 | 2..100000; 401/403 на login paths |
| `error_burst_threshold` | 30 | 2..100000; все 4xx/5xx |
| `login_paths` | `/login`, `/wp-login.php`, `/api/login`, `/api/auth/login` | До 100 точных path без query/fragment |
| `correlation_enabled` | true | Включает bounded correlation |
| `correlation_min_paths` | 2 | 1..1000 общих подозрительных path identities с близкими событиями |
| `correlation_similarity` | 0.7 | 0..1; cosine threshold |
| `correlation_window_seconds` | 300 | 1..86400; максимальная дистанция сопоставленных событий |
| `correlation_max_cluster_size` | 50 | 2..500; deterministic partition cap |

Неопределённость timestamp-resolution важна: пачка событий с одинаковым временем не даёт cadence claim. Auth-детектор не использует HTTP 200 как признак успешного/неуспешного ввода пароля. Добавляйте реальные login paths приложения и проверяйте правила на negative controls.

## `[scoring]` и `[scoring.weights]`

`repetition_bonus_cap=15` (0..30), `medium_threshold=40` (1..99), `high_threshold=70` (2..100). Medium строго ниже high.

Вес любого известного тега — целое число 0..100. Partial override сохраняет defaults остальных тегов. Список и defaults полностью приведены в [config.example.toml](../config.example.toml). Неизвестный тег — configuration error, чтобы typo не «выключал» правило молча.

```toml
[scoring.weights]
SCANNER_UA = 0
SENSITIVE_PATH = 20
```

Это выключает вклад User-Agent и увеличивает вклад служебных путей, не меняя сами evidence. Полная формула — [ARCHITECTURE.md](ARCHITECTURE.md).

## `[privacy]`

- `anonymize_ips=false`: IP нужны оператору для расследования. При true применяется HMAC-SHA256 с domain separation, 24 hex-символами псевдонима; group IDs также псевдонимизируются.
- `include_query=false`: вся query и fragment скрываются в exported references. Анализ всё равно использует полный URL.
- Absolute URL userinfo/authority не экспортируются в request references. URL никогда не превращается в кликабельную attacker-ссылку в HTML.
- Без HMAC key генерируется ephemeral key на запуск. Для стабильных псевдонимов передайте секрет >=32 UTF-8 bytes через environment; ключ не включается в конфиг, отчёт или logging.

Псевдонимы — **не полная анонимизация**: пути, имена файлов, времена и site labels могут раскрывать данные. Любой клиентский отчёт требует review; `result.actors` в Python API содержит raw URL и raw IP.

## `[reporting]`

| Поле | Default | Смысл |
|---|---|---|
| `output_dir` | `reports` | Родитель новых приватных run directories |
| `formats` | `json`, `html`, `text` | 1..3 неповторяющихся формата |
| `max_display_actors` | 100 | 1..10000, только HTML/text |
| `max_evidence_per_actor` | 12 | 1..100, только HTML/text |
| `sample_events` | 3 | 1..20 references на request-level signal |

Behavior/temporal detectors сохраняют до трёх иллюстративных references независимо от `sample_events`. Это sampling evidence, не обрезка анализа. JSON содержит все акторы и все **собранные** evidence, но не весь raw event corpus.

## `[ioc]` и `[[ioc.files]]`

IoC по умолчанию выключен. `enabled=true` требует хотя бы один файл. До 20 фидов, уникальные имена: буквы/цифры/`.`/`_`/`-`, максимум 64 символа.

```toml
[ioc]
enabled = true
max_file_bytes = 1048576
max_entries = 10000

[[ioc.files]]
name = "reviewed-local-ips"
path = "examples/ioc-ips.txt"
type = "ip"
expires_at = "2026-12-31T00:00:00Z"
```

Этот пример синтетический, не production blocklist. Каждая непустая не-комментарная строка — literal indicator. Повторы удаляются.

- `type=ip`: точное IP или CIDR membership, не substring.
- `type=url_path`: точный нормализованный path, без query/fragment, не regex.
- `type=user_agent`: case-insensitive literal substring; дополнительно максимум 128 шаблонов длиной 6..256 символов.
- `max_file_bytes`: 1..10485760; `max_entries`: 1..100000. Отдельный indicator не длиннее 2048 символов.
- `expires_at`: необязательный aware timestamp; по достижении времени фид отклоняется. Без него автоматически определить свежесть нельзя.
- URL источника не принимается; нет скачивания, redirects, refresh daemon или «успешного» анализа со сломанным включённым фидом.

## Environment

| Переменная | Назначение |
|---|---|
| `SIGMA_PROBE_CONFIG` | Config path, если `--config` не указан |
| `SIGMA_PROBE_SITE` | Override site |
| `SIGMA_PROBE_OUTPUT_DIR` | Override output directory |
| `SIGMA_PROBE_LOG_LEVEL` | Override logging level |
| `SIGMA_PROBE_HMAC_KEY` | Только секрет для стабильных псевдонимов, не часть Settings |

Для локальной shell-сессии ключ можно получить через `python3 -c 'import secrets; print(secrets.token_hex(32))'` и поместить в защищённый secret store/environment. Не отправляйте ключ в чат, не сохраняйте в Git и не включайте его в клиентский отчёт. `SIGMA_UID`/`SIGMA_GID` используются только примером Compose, а не CLI.
