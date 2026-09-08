# Миграция Helios 2.x → 3.0.0rc1

Это intentional major-version refactor, не обещание полной обратной совместимости. Исходный CLI pipeline не был работоспособен end-to-end; воспроизведения сохранены в evidence. Смена контрактов нужна для проверяемого продукта, а не для получения зелёных unit-тестов ценой сохранения неверной семантики.

## Что сохранено

Назначение — анализ access-логов; пакет `sigma_probe`; разделение ingestion/features/profiling/detection/scoring/intelligence/reporting; HTML/JSON/text; IP profiles, evidence, группировка сходства и ATT&CK context.

## Намеренные изменения

| Было в архиве | Стало | Причина |
|---|---|---|
| Несогласованные 1.0/2.0, Python 3.9/3.11 | 3.0.0rc1, Python 3.11+ | Один проверяемый контракт |
| Poetry и 12 runtime dependencies | Stdlib, offline PEP 517 wheel/zipapp | Уменьшение установки, supply-chain и невостребованного стека |
| YAML `config.yaml` | `config.example.toml`, validated Settings | Native tomllib; неизвестные поля — ошибки |
| Pydantic models с устаревшими полями | dataclasses с явной runtime validation | Единая модель для всех этапов |
| Заявленный FFT | Честный TemporalDetector по CV | Исходник не вычислял FFT; спектральная детекция не выдается за реализованную |
| Graph centrality «координаторы» и DBSCAN ranks | Suspicious-path cosine + time matching + bounded complete-link partition | Сохраняет идентичность путей, исключает benign visitors и chaining |
| Anomaly/entropy/global multipliers без калибровки | Явные request/behavior signals и additive scoring | Меньше необъяснимых ложных выводов |
| CONFIRMED_BOTNET/CONFIRMED_SOPHISTICATED | MULTIPLE_SIGNALS / CORRELATED_ACTIVITY | Access-log не подтверждает принадлежность ботнету или успех эксплуатации |
| Remote IoC с фиктивными URL | Reviewed local snapshots, точный IP/CIDR | Нет сетевых утечек/SSRF/неявных внешних зависимостей |
| Фиды загружались без применения | IoC входит в event flags и evidence | Работающий end-to-end путь |
| Score без верхней границы | 0–100, raw contributions + cap_adjustment | Интерпретируемый приоритет, не вероятность |
| Recommendation branch использует actor.ip | Типизированные рекомендации с actor_ids | Достижимые ветки, реальная сериализация |
| Reports возвращаются строками | Атомарные files + report schema 1.0 | Реальный пользовательский результат |
| Пропущенный BDD suite | Исполняемые unittest fixtures | Нет pytest/сети/skip requirement |

## Новый интерфейс

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --no-index .
.venv/bin/sigma-probe analyze --input examples/access.log --output reports
```

Старое написание `python -m sigma_probe.main --input ...` сохранено как spelling alias. Имя `HeliosPipeline` — alias класса `AnalysisPipeline`, но возвращает новый `AnalysisResult`, а не старый dict. Старые `FFTDetector`, `AnomalyDetector`, `BehavioralClusteringDetector`, abstract Enricher/PipelineStage не являются стабильным API v3; замените вызов на `AnalysisPipeline` либо новые явные стадии.

## Миграция конфигурации

Не переименовывайте YAML в `.toml`. Переносите только реально используемые параметры в [новую схему](CONFIGURATION.md), проверьте `validate-config`.

- input_file/log_path → `[input].files` array.
- log_format/format → `[input].format`.
- output_formats → `[reporting].formats`.
- min_events_for_fft → `[detection].temporal_min_events`.
- rhythmic_threshold → не переносится автоматически; используйте `temporal_cv` со смыслом CV.
- scoring_profiles/modifiers/tag_combinations → `[scoring.weights]` и bounded repetition. Старые численные score не сопоставимы с 0–100 без повторной калибровки.
- campaign_clustering/DBSCAN eps → новые correlation conditions; это другой алгоритм.
- parallel/max_workers/global modifiers → удалены, не «игнорируются для совместимости».
- ioc_feeds.urls → отдельная процедура загрузки/проверки и локальные `[[ioc.files]]`.

## Изменения событий и отчёта

Canonical JSONL — timestamp/source_ip/method/url/status_code. Старые `http_method`/`url_raw` допустимы как input aliases, но в модели используется одна каноническая пара. `user_agent` необязателен. IPv6 и aware UTC обязательны там, где применимо.

JSON report имеет `schema_version=1.0`. Actor: `ip_address`, `score`, `severity`, `suppressed`, `metrics`, `tags`, `score_breakdown`, `evidence`, `mitre_techniques`. Это не сериализация старого ActorProfile с произвольными extra fields. Group/campaign — эвристическая группа сходства; average score берётся из итоговых actor scores.

## Проверка перед переключением

Сохранить архив/старый config для provenance, провести запуск на одних и тех же snapshots, вручную проверить semantic differences и negative controls. Нельзя считать уменьшение числа «подтверждённых ботнетов» ухудшением recall: исходные labels не были доказательством ботнета. Оценивать полезность нужно по размеченным событиям и реальным действиям аналитика.
