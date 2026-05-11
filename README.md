<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1b27,50:3670A0,100:1a1b27&height=200&section=header&text=SIGMA-PROBE&fontSize=50&fontColor=FFFFFF&fontAlignY=35&desc=Helios%20v2.0%20--%20Advanced%20Threat%20Analysis%20Engine&descSize=16&descColor=ffdd54&descAlignY=55&animation=fadeIn" width="100%"/>

<div align="center">

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3670A0?style=flat-square&logo=python&logoColor=ffdd54)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-blue?style=flat-square)]()
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen?style=flat-square)]()
[![Poetry](https://img.shields.io/badge/poetry-managed-blueviolet?style=flat-square&logo=poetry)](https://python-poetry.org)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)

**🇷🇺 [Русский](#-описание) · 🇬🇧 [English](#-overview)**

</div>

---

## 🇬🇧 Overview

**SIGMA-PROBE Helios v2.0** is a modular security telemetry analysis engine that identifies malicious actors and coordinated threat campaigns by processing web access logs through a multi-stage enrichment and detection pipeline.

It transforms static log data into a live behavioral picture — detecting automated scanners, coordinated botnets, and sophisticated multi-stage attacks through FFT spectral analysis, graph-based clustering, and MITRE ATT&CK tagging.

### Key Capabilities

| Feature | Description |
|:---|:---|
| **Multi-dimensional Tagging** | Actors receive multiple behavioral tags instead of a single tactic classification |
| **FFT Spectral Detection** | Catches periodic bot patterns, even with jitter, via Fast Fourier Transform |
| **Graph Campaign Clustering** | Identifies coordinated attackers using NetworkX betweenness centrality |
| **Behavioral Vectors** | 50-dimension normalized vectors + cosine similarity for attack grouping |
| **MetaDetector ("Council of Directors")** | Cross-validates findings across detectors, resolves false positives |
| **MITRE ATT&CK Mapping** | Professional threat classification with actionable recommendations |
| **Data-Driven Config** | All thresholds, modifiers, and rules in YAML — no recompilation needed |
| **Dynamic IoC Feeds** | Auto-updating threat intelligence from external sources |

### Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Ingestion     │    │   Enrichment    │    │   Profiling     │
│   (Nginx/Apache │───▶│   (Features +   │───▶│   (Actor        │
│    JSON logs)   │    │    Heuristics)  │    │    Aggregation) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────▼───────┐
│   IoC Feeds     │    │   Detection     │    │  MetaDetection  │
│   (Threat Intel)│───▶│   (FFT/Graph/   │───▶│  (Cross-Valid + │
│                 │    │    Anomaly)     │    │   Confirmation) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────▼───────┐
│   Reporting     │◀───│  Narrative +    │◀───│   Scoring       │
│   (Evidence     │    │  Recommendations│    │   (Rules Engine │
│    Trail)       │    │  (MITRE ATT&CK) │    │    + Campaigns) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Quick Start

```bash
# Install dependencies
poetry install

# Run analysis on access log
poetry run python -m sigma_probe.main --config config.yaml --input access.log

# Run tests
poetry run pytest -v

# Run with Docker
docker build -t sigma-probe .
docker run -v $(pwd)/logs:/data sigma-probe --input /data/access.log
```

### Project Structure

```
src/sigma_probe/
├── models/
│   └── core.py              # LogEvent, ActorProfile data models
├── pipeline/
│   ├── base.py              # Abstract Pipeline, Enricher, Detector
│   ├── ingestion.py         # Nginx, Apache, JSON log parsing
│   ├── profiling.py         # Actor aggregation & behavioral metrics
│   ├── detectors.py         # FFT, Graph, Anomaly detection
│   ├── metadetector.py      # Cross-validation & false-positive resolution
│   ├── scoring.py           # Behavioral clustering & campaign grouping
│   └── rules_engine.py      # YAML-driven threat scoring
├── intelligence/            # IoC feeds & threat intel
└── main.py                  # CLI entrypoint
tests/
├── test_detectors.py        # Detection logic tests
├── test_models.py           # Data model tests
├── test_scoring.py          # Scoring engine tests
└── test_lfi_scenario.py     # BDD threat scenario tests
```

### Tech Stack

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![NetworkX](https://img.shields.io/badge/NetworkX-4B8BBE?style=for-the-badge)
![Pandas](https://img.shields.io/badge/pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/numpy-013243?style=for-the-badge&logo=numpy&logoColor=white)
![Docker](https://img.shields.io/badge/docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)

---

## 🇷🇺 Описание

**SIGMA-PROBE Helios v2.0** — модульный аналитический движок для анализа угроз безопасности. Обрабатывает логи веб-серверов через многоэтапный конвейер обогащения и детекции, выявляя вредоносных акторов и координированные атаки.

### Ключевые Инновации

<details>
<summary><b>1. Система Тегов вместо "Диктатуры Первой Тактики"</b></summary>

- **Многомерная классификация**: Акторы получают множественные теги вместо одной тактики
- **Комбинационный анализ**: Система понимает взаимодействие тегов (LFI + AUTOMATED_SCAN = критическая угроза)
- **Контекстная оценка**: Угроза оценивается на основе комбинации поведенческих паттернов
</details>

<details>
<summary><b>2. FFT Спектральный Анализ</b></summary>

- **FFT + Автокорреляция**: Обнаружение нестрого периодических паттернов
- **Оконный анализ**: Выявление резких изменений частоты запросов
- **Адаптивные боты**: Ловля sophisticated атак с джиттером
</details>

<details>
<summary><b>3. Графовая Кластеризация Кампаний</b></summary>

- **Векторы поведения**: 50-мерные нормализованные векторы
- **Косинусное расстояние**: Точное определение схожести атак
- **Betweenness Centrality**: Выявление координаторов через NetworkX
</details>

<details>
<summary><b>4. "Совет Директоров" (MetaDetector)</b></summary>

- **Cross-validation**: Перепроверка выводов всех детекторов
- **Подтверждения**: CONFIRMED_BOTNET, CONFIRMED_COORDINATED
- **Разрешение противоречий**: ISOLATED_INDICATOR, FALSE_POSITIVE
</details>

<details>
<summary><b>5. Narrative Engine + MITRE ATT&CK</b></summary>

- **Actionable рекомендации**: Система предлагает конкретные решения
- **Маппинг**: Профессиональный язык кибербезопасности
- **Приоритизация**: HIGH/MEDIUM/LOW с конкретными действиями
</details>

### Быстрый старт

```bash
# Установка зависимостей
poetry install

# Запуск анализа
poetry run python -m sigma_probe.main --config config.yaml --input access.log

# Запуск тестов
poetry run pytest -v

# Docker
docker build -t sigma-probe .
docker run -v $(pwd)/logs:/data sigma-probe --input /data/access.log
```

### Пример вывода

```json
{
  "actor": "203.0.113.42",
  "threat_level": "CRITICAL",
  "score": 94.7,
  "tags": ["AUTOMATED_SCAN", "LFI_PROBE", "CREDENTIAL_STUFFING"],
  "campaign": "campaign_alpha_7",
  "mitre_tactics": ["TA0043", "TA0001", "TA0006"],
  "recommendations": [
    {"priority": "HIGH", "action": "Block IP range 203.0.113.0/24"},
    {"priority": "MEDIUM", "action": "Enable WAF rule for path traversal"}
  ]
}
```

---

<div align="center">

### License

MIT — see [LICENSE](LICENSE) for details.

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1b27,50:3670A0,100:1a1b27&height=80&section=footer" width="100%"/>

</div>
