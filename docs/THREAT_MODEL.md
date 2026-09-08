# Модель угроз и ограничения детекции

## Активы и границы доверия

URL, User-Agent, JSON и forwarded headers в логах могут быть сформированы внешним клиентом. Защищаем локальную машину анализатора, целостность выводов, приватность логов, HMAC key и доступ к готовому отчёту. Содержимое логов — данные, не исполняемые команды.

Конфигурация и локальные IoC snapshots доверенные по происхождению, но проходят валидацию и size limits. Один запуск — конечный batch одного сайта под отдельным OS account. Multi-tenant SaaS с произвольными remote paths не реализован.

## Меры и остаточные риски

| Риск | Реализовано | Что остаётся оператору |
|---|---|---|
| HTML/script injection | Escaping всех dynamic scalars, CSP default-src none, нет JS/CDN, payload URL не ссылки | Проверка смысла текста перед передачей |
| Query/tokens leakage | Общая privacy projection, query/fragment скрыты по умолчанию | Секреты могут находиться в path, site label и имени файла |
| Раскрытие IP | Опциональный keyed HMAC, отдельные group pseudonyms | Это псевдонимизация, не полная анонимизация |
| Подмена client IP | XFF игнорируется без explicit trusted peer; обход справа налево | Проверить реальные proxy CIDR и их конфигурацию |
| Cross-site grouping | Разные явные JSON hosts отвергаются | Combined без host не доказывает изоляцию; разделяйте snapshots |
| SSRF/удалённые фиды | Нет runtime network calls; IoC только local | Проверка provenance и содержательной точности snapshots |
| Substring IP matches | Exact IP/CIDR membership | Широкий CIDR может быть содержательно ошибочен |
| Regex abuse | Нет пользовательских regex; bounded literal UA patterns | Fixed signatures не исчерпывают payloads |
| Gzip bomb/oversized records | Decompressed byte budget, bounded readline, event/actor limits | OS-level RSS/CPU/disk caps нужны отдельно |
| Graph blow-up | Inverted index и explicit candidate/work budgets | Плотный batch может быть отклонён, не «частично успешен» |
| Corrupt/partial reports | Private staging, exclusive writes, fsync, atomic directory rename | SIGKILL/сбой питания/необычная FS могут оставить staging |
| Output symlinks/overwrite | Unique run dir, конечный root не symlink и не group/world writable | Same-UID attacker, небезопасные ancestors и сетевые ACL вне гарантии |
| Parser diagnostic leakage | Только input ID/line/reason, до 20 error samples | Debug stderr доступен доверенному оператору |
| Ложная уверенность | Evidence, score breakdown, explicit limitations, no confirmed-botnet label | Разметка и калибровка реальных данных |

## Чего access-log не доказывает

- Успех exploit по HTTP 200, исполнение команд backend, чтение строк БД.
- Принадлежность ботнету/одному оператору, наличие C2, полную цепочку инцидента.
- Содержимое request body/cookies и application auth outcomes, которых нет во входном формате.
- Отсутствие атак за пределами supplied files/time window либо в потерянных строках.

ATT&CK T1190/T1595/T1110 — контекст паттерна, не подтверждённая техника. [T1190](https://attack.mitre.org/techniques/T1190/) требует сопоставления с дополнительной серверной телеметрией. Cadence не маппится автоматически на C2/FTP/non-standard-port.

## False positives / false negatives

Возможные false positives: разрешённый scanner, поисковый query, legitimate file parameter, login storm за NAT, application outage, monitoring. Allowlist — только после проверки происхождения. Сходство нескольких IP не доказывает причинность.

Возможные false negatives: custom payloads, глубокое кодирование сверх двух проходов, body-only атаки, endpoint-specific логика, low-and-slow, distributed activity ниже порогов, недостаточное timestamp resolution. Здесь нет trained model или полного WAF rule set.

Negative controls должны включать health checks, обычные PHP-страницы, redirects, поисковых ботов, API и shared proxy/NAT. Score — приоритет ручной проверки, не вероятность компрометации.

## Эксплуатация

Read-only finite snapshots, non-root, one site per job, runtime network deny, OS resource caps, private output, раздельные HMAC keys и reviewed IoC с expiry. Проверяйте код 4 и invalid/filtered counts. Не публикуйте raw логи в issues.

`result.report` в API прошёл privacy projection; `result.actors` всё ещё содержит raw IP/URL. Это не автоматическое GDPR/compliance соответствие. Выполненные проверки и внешние gates разделены в [VALIDATION.md](VALIDATION.md).
