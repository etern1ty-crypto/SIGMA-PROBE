# Совместимость форматов: проверенный объём

| Источник | Режим | Подтверждение | Граница |
|---|---|---|---|
| Nginx default combined | `auto`/`nginx`/`combined` | `examples/access.log`, CLI и unit-тесты | Дополнительные поля в конце строки не поддерживаются этим шаблоном |
| Apache common/combined | `common`/`combined` | fixtures и unit-тесты | Нестандартные custom formats требуют JSONL-профиля |
| Angie/Nginx `escape=json` | `auto`/`jsonl` | [готовый log_format](../examples/angie-nginx-log-format.conf), fixture с кириллицей/`+03:00` и [end-to-end replay обоих серверов](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/runs/35846770795) | Проверены указанные версии контейнерных образов, не произвольные конфигурации |
| Сжатые ротации | `.gz` | тесты декомпрессии, лимитов, ошибок и хешей | SHA-256 в отчёте относится к распакованным байтам |
| Конечный поток | `-` | CLI tests | Нет follow/tail режима |

Все timestamp приводятся к UTC. `X-Forwarded-For` используется только при явной настройке `trusted_proxy_cidrs` и разборе цепочки справа налево. В JSONL `host` должен указывать один сайт на запуск; различающиеся host приводят к ошибке.

Собранный `.pyz` прошёл `analyze` и `verify-report` без сети, от непривилегированного пользователя и с read-only rootfs в [официальных контейнерных образах](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/runs/35846770795): Astra Linux 1.8 (`ubi18-python311`), РЕД ОС 8 (`python-313-minimal`) и ALT Linux p11 (`python:3.12.7`). Это проверка пользовательского окружения контейнера, **не** нативной установки, политики безопасности хоста или сертифицированной редакции ОС.

Формат `escape=json` и директива `access_log` сверены с [документацией Angie](https://en.angie.software/angie/docs/configuration/modules/http/http_log/) и [Nginx](https://nginx.org/en/docs/http/ngx_http_log_module.html). Их реальные бинарники в указанных контейнерах приняли конфигурацию и сгенерировали разобранные логи в CI.
