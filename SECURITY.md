# Security policy

## Статус

3.0.0rc1 — проверяемый candidate, не SLA/сертификация/гарантия полноты детекции. См. [VALIDATION.md](docs/VALIDATION.md) и [THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Сообщить об уязвимости

В исходном архиве нет подтверждённого private security contact или настроенного GitHub security channel. Здесь не выдумывается email/URL. Перед public release владелец должен включить private vulnerability reporting и опубликовать подтверждённый контакт.

До этого передавайте сведения владельцу используемой копии по существующему приватному каналу. Укажите version/Python/ОС, минимальный synthetic reproducer, ожидаемое/фактическое поведение и trust boundary. Не публикуйте raw client logs, tokens, HMAC keys и отчёты с PII.

## Оператору

- Обрабатывайте только данные, на которые есть полномочия.
- Read-only finite snapshots, один сайт, non-root, private output.
- Query скрыт по умолчанию; передавайте отчёты только после review.
- HMAC keys — secret store, не Git; отдельные ключи для клиентов.
- Обновляйте Python и OS/container image по своей security procedure.
- Не превращайте scores/groups в автоматические массовые блокировки.
- Remote API требует отдельной auth/tenant/job-quota архитектуры.
- Code 4 — неполный вход; code 2/130/143 нужно разбирать отдельно.

Runtime не обращается к сети. Но Python, base image, CI и операционные инструменты имеют собственную поверхность угроз. Ноль сторонних Python-пакетов не означает ноль CVE во всём deployment.
