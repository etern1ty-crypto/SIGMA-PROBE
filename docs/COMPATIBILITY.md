# Совместимость форматов: проверенный объём

| Источник | Режим | Подтверждение | Граница |
|---|---|---|---|
| Nginx default combined | `auto`/`nginx`/`combined` | `examples/access.log`, CLI и unit-тесты | Дополнительные поля в конце строки не поддерживаются этим шаблоном |
| Apache common/combined | `common`/`combined` | fixtures и unit-тесты | Нестандартные custom formats требуют JSONL-профиля |
| Angie/Nginx `escape=json` | `auto`/`jsonl` | [готовый log_format](../examples/angie-nginx-log-format.conf), fixture с кириллицей/`+03:00` и [Nginx replay в CI](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/runs/35845259275) | Реальный бинарник Angie не запускался |
| Сжатые ротации | `.gz` | тесты декомпрессии, лимитов, ошибок и хешей | SHA-256 в отчёте относится к распакованным байтам |
| Конечный поток | `-` | CLI tests | Нет follow/tail режима |

Все timestamp приводятся к UTC. `X-Forwarded-For` используется только при явной настройке `trusted_proxy_cidrs` и разборе цепочки справа налево. В JSONL `host` должен указывать один сайт на запуск; различающиеся host приводят к ошибке.

Для Astra Linux, RED OS и ALT Linux пока подтверждена только переносимость исходного кода на Python 3.11+ как архитектурный замысел, **не** системное тестирование на этих ОС. Перед заявлением совместимости нужны реальные установки/контейнеры, проверка версии Python, кодировки, прав каталога отчётов и контрольный replay.

Формат `escape=json` и директива `access_log` сверены с [документацией Angie](https://en.angie.software/angie/docs/configuration/modules/http/http_log/) и [Nginx](https://nginx.org/en/docs/http/ngx_http_log_module.html). Nginx end-to-end проверен в CI; для Angie пока есть только сверка синтаксиса и парсерные fixtures.
