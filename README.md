# 🚀 SIGMA-PROBE Helios v2.0

[![CI](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/workflows/ci.yml/badge.svg)](https://github.com/etern1ty-crypto/SIGMA-PROBE/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Advanced Modular Threat Analysis Framework**

Архитектура v2.0 - 'Helios' представляет собой квантовый скачок в области анализа угроз. Это не просто система детекции - это интеллектуальный аналитический движок, способный понимать сложные многоэтапные атаки и принимать контекстные решения.

## 🌟 Ключевые Инновации v2.0

### 1. Система Тегов вместо "Диктатуры Первой Тактики"
- **Многомерная классификация**: Акторы получают множественные теги вместо одной тактики
- **Комбинационный анализ**: Система понимает взаимодействие тегов (LFI + AUTOMATED_SCAN = критическая угроза)
- **Контекстная оценка**: Угроза оценивается на основе комбинации поведенческих паттернов

### 2. Data-Driven Конфигурация
- **Полная настройка через YAML**: Все пороги, модификаторы и правила в конфигурации
- **Гибкость без перекомпиляции**: Изменение логики без изменения кода
- **Профили скоринга**: Контекстные профили для разных типов угроз

### 3. Межмодульное Взаимодействие
- **Контекстный обмен**: Детекторы обмениваются мета-информацией
- **Глобальная осведомленность**: Система видит "лес", а не только "деревья"
- **Адаптивные решения**: Скоринг учитывает общую обстановку

### 4. Поведенческая Кластеризация
- **Векторы поведения**: Кластеризация по намерениям, а не по метрикам
- **Косинусное расстояние**: Точное определение схожести атак
- **Семантическая группировка**: Акторы с похожими целями группируются вместе

### 5. Элегантная Архитектура
- **Разделение ответственности**: RulesEngine отвечает за "КАК", ScoringEngine за "ЧТО"
- **Умные модели**: LogEvent сам рассчитывает свои признаки
- **Чистый код**: Один этап - один модуль

### 6. Параллельная Обработка
- **Многопроцессорная обработка**: До 4 воркеров одновременно
- **Умное распределение**: Автоматическое распределение нагрузки
- **Масштабируемость**: Горизонтальное масштабирование

### 7. Адаптивный Временной Анализ
- **FFT + Автокорреляция**: Обнаружение нестрого периодических паттернов
- **Оконный анализ**: Выявление резких изменений частоты запросов
- **Адаптивные боты**: Ловля sophisticated атак с джиттером

### 8. Динамические IoC Фиды
- **Внешние источники угроз**: Автоматическое обновление из threat intelligence
- **Самообновляемость**: Система остается актуальной без изменения кода
- **Множественные типы IoC**: user_agent, url_path, ip_address, url_pattern

### 9. "Совет Директоров" (MetaDetector)
- **Cross-validation**: Анализ и перепроверка выводов детекторов
- **Подтверждения угроз**: CONFIRMED_BOTNET, CONFIRMED_COORDINATED
- **Разрешение противоречий**: ISOLATED_INDICATOR, FALSE_POSITIVE

### 10. Narrative Engine
- **Actionable рекомендации**: Система предлагает решения, а не только показывает проблемы
- **MITRE ATT&CK маппинг**: Профессиональный язык кибербезопасности
- **Приоритизация**: HIGH/MEDIUM/LOW рекомендации с конкретными действиями

### 11. Behavioral Testing (BDD)
- **Сценарии угроз**: Реалистичные тестовые атаки
- **Проверка интеллекта**: Тестирование поведения системы, а не кода
- **Комплексная валидация**: От детекции до кластеризации кампаний

## 🏗️ Архитектура

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Ingestion     │    │   Enrichment    │    │   Profiling     │
│   (Loading)     │───▶│   (Features)    │───▶│   (Actors)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   IoC Feeds     │    │   Detection     │    │   MetaDetection │
│   (Threat Intel)│───▶│   (Tags)        │───▶│   (Cross-Valid) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Reporting     │◀───│   Recommendations│◀───│   Scoring       │
│   (Evidence)    │    │   (Narrative)   │    │   (Rules)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🧠 Интеллектуальные Компоненты

### Data Models (Domain-Specific)
```python
class LogEvent:
    def calculate_features(self) -> None:
        # Встроенный расчет всех признаков
        self._calculate_entropy()
        self._calculate_url_features()
        self._apply_heuristics()

class ActorProfile:
    tags: Set[str] = Field(default_factory=set)  # Система тегов
    evidence_trail: List[Dict[str, Any]]         # След доказательств
    url_frequency_vector: Dict[str, float]       # Поведенческий вектор
```

### Rules Engine
```python
class ScoringRulesEngine:
    def calculate_score(self, actor: ActorProfile, context: Dict[str, Any]) -> Tuple[float, List[Dict[str, Any]]]:
        # Интерпретация правил из config.yaml
        # Применение модификаторов
        # Генерация evidence trail
```

### Detection Engine
- **FFTDetector**: Ритмические паттерны и автоматизация
- **GraphDetector**: Координация и центральность
- **AnomalyDetector**: Аномальное поведение
- **BehavioralClusteringDetector**: Поведенческая кластеризация

### Contextual Scoring
```yaml
scoring_profiles:
  LFI_RFI:
    base_score: 8.0
    modifiers:
      - if: 'high_entropy'
        value: 1.3
        evidence: "LFI/RFI with high entropy - likely encoded payload"
      - if: 'coordinated_attack'
        value: 1.5
        evidence: "LFI/RFI as part of coordinated attack"
```

## 🚀 Быстрый Старт

### Установка
```bash
git clone https://github.com/etern1ty-crypto/SIGMA-PROBE.git
cd SIGMA-PROBE

# Editable install (подходит и для pip, и для uv):
python -m pip install -e .
python -m pip install pytest pytest-cov
```

Проект использует `pyproject.toml` (PEP 621 через Poetry). Python ≥3.11 рекомендуется —
stack `numpy/scipy/pandas/networkx` на 3.12 с более старыми версиями может потребовать сборки
из исходников. Для воспроизводимости создайте виртуальное окружение:

```bash
python3.11 -m venv .venv && source .venv/bin/activate
# или через uv:
# uv venv --python 3.11 .venv && source .venv/bin/activate
```

### Конфигурация
Отредактируйте `config.yaml`:
```yaml
ingestion:
  input_file: "your_logs.log"
  log_format: "nginx"

detection:
  detectors:
    - FFTDetector
    - GraphDetector
    - AnomalyDetector
    - BehavioralClusteringDetector

pipeline:
  parallel:
    enabled: true
    max_workers: 4
```

### Запуск
```bash
# Полный анализ (читает input_file из config.yaml — по умолчанию sample_nginx.log)
python -m sigma_probe.main

# Unit-тесты
python -m pytest tests/ -v
```

Текущий статус тестового прогона: **39 passed, 5 skipped** (BDD-сценарий с LFI-фиксурой временно
пропущен — см. раздел «Что покрыто, а что нет» ниже).

## 📊 Примеры Вывода

### Система Тегов с MITRE ATT&CK
```
Actor: 192.168.1.100
Tags: [LFI_ATTACK, CONFIRMED_BOTNET, CONFIRMED_SOPHISTICATED]
MITRE Techniques: [T1083 - File and Directory Discovery, T1190 - Exploit Public-Facing Application]
Threat Score: 12.8 (высокий из-за комбинации тегов)
Evidence: 
  - FFTDetector: Detected adaptive timing with frequency changes
  - HeuristicEnricher: LFI/RFI pattern detected in URL
  - MetaDetector: Cross-validation confirms sophisticated attack
  - IoC Feed: Pattern matched from external threat intelligence
```

### Actionable Рекомендации
```
HIGH PRIORITY - Sophisticated LFI Attack - 192.168.1.100
Description: Обнаружена изощренная LFI-атака с адаптивным поведением
MITRE Techniques: T1083, T1190

Action Items:
1. Немедленно заблокировать IP 192.168.1.100 на файрволе (уровень 7)
2. Провести аудит прав доступа для веб-сервера
3. Проверить все скрипты, работающие с инклудами (include, require)
4. Обновить WAF правила для блокировки path traversal
5. Проверить логи на предмет успешных попыток доступа к системным файлам

Confidence: 95%
```

### Контекстный Скоринг
```
Global Context:
  - FFT Summary: 15/50 actors show rhythmic patterns (30% prevalence)
  - Graph Summary: 5 coordinators detected
  - Anomaly Summary: 8 anomalous actors (16% rate)

Actor Scoring:
  - Base Score: 8.0 (LFI_RFI)
  - Tag Combination: 1.8x (LFI_RFI + COORDINATED_ATTACK)
  - Context Modifier: 1.2x (part of widespread attack)
  - Final Score: 17.28
```

## 🔧 Расширенная Конфигурация

### Tag Combinations
```yaml
tag_combinations:
  "LFI_RFI+COORDINATED_ATTACK":
    multiplier: 1.8
    evidence: "LFI/RFI in coordinated attack - highly dangerous"
  
  "COMMAND_INJECTION+COORDINATOR":
    multiplier: 2.0
    evidence: "Command injection by coordinator - critical threat"
```

### Evidence Trail
```yaml
evidence_trail:
  enabled: true
  max_entries_per_actor: 10
  include_confidence: true
  include_timestamps: true
```

### Parallel Processing
```yaml
pipeline:
  parallel:
    enabled: true
    max_workers: 4
```

## 📈 Производительность

- **Параллельная обработка**: До 4 воркеров одновременно
- **Пакетная обработка**: До 10,000 событий за раз
- **Кэширование**: Умное кэширование результатов
- **Оптимизированные алгоритмы**: FFT, Graph Analysis, Clustering

## 🧪 Тестирование

### Unit-тесты
```bash
python -m pytest tests/
```

### Покрытие тестами
```bash
python -m pytest tests/ --cov=sigma_probe --cov-report=html
```

### Что покрыто, а что нет
- **Покрыто**: модели (`LogEvent`, `ActorProfile`), эвристики, скоринг (`ScoringRulesEngine`), детекторы (`FFT`, `Graph`, `Anomaly`).
- **Пропущено**: end-to-end BDD-сценарий `tests/test_lfi_scenario.py` — требует фиксуру `tests/scenarios/lfi_attack_scenario.log` и поддержку `HeliosPipeline.run(log_path)`. Класс помечен `@pytest.mark.skip` с явной причиной; восстанавливать обе части — отдельная задача.

CI автоматически прогоняет pytest на каждом push/PR через `.github/workflows/ci.yml`.

## 🎯 Преимущества v2.0

### Для Аналитиков
- **Понятные отчеты**: Evidence trails показывают "почему" и "как"
- **Контекстная информация**: Система объясняет свои решения
- **Гибкая настройка**: Адаптация под специфику инфраструктуры

### Для Инженеров
- **Модульная архитектура**: Легкое добавление новых детекторов
- **Data-driven подход**: Конфигурация без изменения кода
- **Масштабируемость**: Горизонтальное масштабирование
- **Надежность**: Полное покрытие unit-тестами

### Для Безопасности
- **Многоэтапные атаки**: Понимание сложных сценариев
- **Координация**: Обнаружение групповых атак
- **Адаптивность**: Обучение на новых паттернах

## 🔮 Будущие Развития

- **Machine Learning**: Интеграция с ML моделями
- **Real-time Processing**: Обработка в реальном времени
- **API Integration**: REST API для интеграции
- **Dashboard**: Веб-интерфейс для мониторинга

## 📝 Лицензия

MIT License - см. LICENSE файл для деталей.

---

## 🤝 Сообщество и Развитие

### Присоединяйтесь к Развитию

SIGMA-PROBE - это open-source проект, и мы приветствуем вклад сообщества!

- 📖 **[CONTRIBUTING.md](CONTRIBUTING.md)** - Подробное руководство по участию
- 🐛 **[Issues](https://github.com/etern1ty-crypto/SIGMA-PROBE/issues)** - Сообщайте о багах и предлагайте улучшения
- 💡 **[Discussions](https://github.com/etern1ty-crypto/SIGMA-PROBE/discussions)** - Обсуждайте архитектуру и новые возможности

### Good First Issues

Для новых контрибьюторов:
- 🔍 Добавить детектор для атак на API (GraphQL/REST)
- 📊 Реализовать выгрузку отчетов в S3
- 📝 Добавить поддержку новых форматов логов

### Архитектура для Расширения

SIGMA-PROBE построен для легкого расширения:
- **Модульные детекторы**: Добавляйте новые алгоритмы детекции
- **Плагинная система**: Интегрируйте внешние источники данных
- **Конфигурируемые правила**: Настраивайте логику без изменения кода

---

**SIGMA-PROBE Helios v2.0** - где искусственный интеллект встречается с кибербезопасностью. 🚀

*Создано с ❤️ для сообщества кибербезопасности* 