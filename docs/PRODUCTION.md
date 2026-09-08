# Развёртывание и Production

## Статус поставки

Это проверяемый **release candidate 3.0.0rc1**, а не обещание отсутствия всех багов. Рабочий CLI, parser/detection/reporting код и локальные тесты реализованы. Матрица доказательств находится в [VALIDATION.md](VALIDATION.md).

**Перед production/public distribution остаются внешние release gates:**

1. Получить подтверждённую upstream-лицензию; в исходном архиве нет полного grant. [LICENSE](../LICENSE), [NOTICE](../NOTICE).
2. Провести пилот на разрешённых размеченных логах, настроить пороги и negative controls; synthetic tests не измеряют precision/recall.
3. Выполнить Docker build/run и CI на целевых версиях Python/ОС; здесь Docker daemon недоступен.
4. Проверить актуальные advisories для выбранного Python и OS/container base, зафиксировать approved image digest и Actions SHAs. Отсутствие сторонних Python-пакетов не исключает уязвимости интерпретатора/ОС.
5. Проверить операции с логами, secret retention, report access, ограничения памяти/диска и обработку exit codes.

## Установка

### Offline source install

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-index .
.venv/bin/sigma-probe --version
```

В минимальном Linux образе может понадобиться системный пакет для `venv`/`ensurepip`. Это свойство Python-дистрибутива, не runtime-зависимость проекта.

### Wheel

```bash
python3 scripts/build_dist.py
.venv/bin/python -m pip install --no-index --no-deps dist/sigma_probe-3.0.0rc1-py3-none-any.whl
.venv/bin/python -m pip check
```

PEP 517 backend проекта использует только stdlib, формирует METADATA, license-status files, entry point и RECORD hashes. Он узко предназначен для этого pure-Python пакета; arbitrary build plugins не поддерживаются.

### Portable zipapp

```bash
python3 dist/sigma-probe.pyz analyze --input examples/access.log --output reports
```

Работает без pip/site-packages, но Python 3.11+ всё равно нужен. Zipapp не является native executable. Не распаковывает и не исполняет содержимое логов.

## Docker

[Dockerfile](../Dockerfile) — multi-stage build; финальная стадия устанавливает только project wheel и запускается непривилегированно. Batch command не получает restart-loop.

```bash
docker build -t sigma-probe:3.0.0rc1 .
mkdir -p reports
chmod 700 reports
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 1g --cpus 1 \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "$PWD/examples:/logs:ro" -v "$PWD/reports:/reports:rw" \
  sigma-probe:3.0.0rc1 analyze -i /logs/access.log -o /reports --site demo-site
```

Выполняйте это от отдельного непривилегированного host account, не root. Reports bind mount должен быть доступен указанному UID/GID. Запуск контейнера без `--user` использует образный UID/GID 10001; подготовьте ownership volume под него.

С [docker-compose.yml](../docker-compose.yml):

```bash
mkdir -p reports && chmod 700 reports
SIGMA_UID="$(id -u)" SIGMA_GID="$(id -g)" docker compose run --rm sigma-probe
```

Для production задайте `PYTHON_IMAGE` утверждённым образом с digest через build arg. В поставке оставлен читаемый `python:3.13-slim`, а не выдуманный digest. Pull base image — этап deployment/build с сетевыми правами, **runtime приложения сети не требует**. Структура Docker/Compose проверена статически; реальная сборка/изоляция контейнера в текущем sandbox не доказана.

## Права и файлы

- Работать от отдельного пользователя; входные snapshots — read-only.
- Отдельный каталог отчётов для каждого клиента, не общий webroot.
- На POSIX run directories создаются `0700`, report files — `0600`.
- Конечный output root не может быть symlink или group/world-writable. Доверенные ancestor mounts разрешаются один раз: например, `/data` или `/var` иногда являются symlink.
- Защита не обещает безопасность при злоумышленнике с тем же OS UID или правом менять доверенных ancestors. Такой процесс уже находится в вашей trust boundary.
- Не использовать world-writable output каталог, небезопасный NFS share или неизвестные directory ACL. POSIX mode checks не являются универсальной оценкой сетевых ACL.

Отчёты сначала пишутся в `.sigma-probe-*` staging внутри destination root, flush/fsync выполняется для файлов; затем один rename публикует весь bundle. Поддерживаемый parent directory fsync повышает crash durability. Нет общей транзакции с cron/stdout/другими системами.

При обычной ошибке/контролируемом сигнале staging удаляется. При SIGKILL/сбое питания могут остаться скрытые staging directories: проверять по возрасту после того, как убедились, что процесс не работает; удалять только staging конкретного job, не весь `reports/`. Готовые timestamp/UUID-папки не перезаписываются и автоматически не удаляются.

## Плановые запуски

Это one-shot job. Scheduler должен передавать конечные **стабильные snapshots**, а не `tail -f`. Нет watermark/incremental state и автоматической дедупликации overlapping rotations.

Пример cron под отдельным account после установки в `/opt/sigma-probe/.venv`:

```cron
15 3 * * * /opt/sigma-probe/run-client-a.sh
```

Создайте `/opt/sigma-probe/run-client-a.sh` со следующим содержимым и разрешите выполнение владельцу. Пути соответствуют описанному deployment; заранее обеспечьте read-доступ к snapshot и write-доступ к `/var/lib/sigma-probe/client-a`:

```sh
#!/bin/sh
set -u
umask 077
root=/var/lib/sigma-probe/client-a
mkdir -p "$root/job-results" || exit 2
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
status=0
/opt/sigma-probe/.venv/bin/sigma-probe analyze \
  --input /srv/log-snapshots/client-a/access.log --site client-a \
  --output "$root/reports" --fail-on high \
  > "$root/job-results/${run_id}.json" \
  2> "$root/job-results/${run_id}.log" || status=$?
printf 'SIGMA-PROBE exit code: %s\n' "$status"
exit "$status"
```

Каждый запуск получает отдельные stdout JSON/stderr файлы с приватным umask. CLI stdout — многострочный JSON, не JSONL: не используйте прямой append нескольких объектов как JSONL.

Обработайте: 0 — обработка завершена, 3 — findings, 4 — partial input, 2 — конфигурация/вход/I/O/budget, 130/143 — interruption. Интеграции с alerting/issue tracker здесь не выданы за реализованные. Cron сам по себе не заменяет сбор статусов и alerting.

## Ресурсы

Defaults: 100000 событий, 10000 IP, 256 MiB распакованного входа, 64 KiB на строку, 100000 candidate pairs и 1000000 evaluation units. Это ограничения данных/работы, **не жёсткий RSS cap**.

Память зависит от URL lengths, количества акторов, совпадений path identities, references и JSON projection. Синтетический benchmark в evidence — ориентир конкретной машины, не прогноз на сырые production-логи. Установите OS/container CPU/memory/pid/дисковые лимиты, следите за exit/OOM status, делите вход на ограниченные окна.

При плотной корреляции можно уменьшить окно, разделить snapshots по сайту/времени или явно выключить correlation. Не делайте этого для получения «зелёного» отчёта: document the scope change. Превышение бюджета не выдаётся за успешный частичный анализ.

## Мониторинг и приватность

Собирать: exit code, input_status, accepted/invalid/filtered counts, elapsed time, output location, версии и hashes. Stderr может содержать пути/диагностику при debug — доступ ограничить.

Query отключён по умолчанию. Для внешнего отчёта рассмотрите `--anonymize-ips`, отдельный HMAC key на клиента и review путей/названий. Не храните client logs и reports в Git. HMAC key в secret store; `.env.example` не содержит рабочего секрета. Регламент retention/удаления, право на обработку и договорные требования определяет оператор; проект не заявляет автоматическое GDPR/compliance соответствие.

## Обновление и rollback

1. Сохранить предыдущий wheel/zipapp и применимую config snapshot.
2. Проверить новую версию на synthetic fixtures и утверждённом corpus.
3. Сравнить изменения schema/rules и false positives вручную.
4. Переключить scheduler на новую версию; не смешивать два запуска на один raw streaming input.
5. Для rollback вернуть предыдущий wheel/zipapp/config; ранее сформированные bundles неизменны.

Не публикуйте RC в package index до разрешения лицензии и CI gates. [MIGRATION.md](MIGRATION.md) фиксирует breaking changes.
