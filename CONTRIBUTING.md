# Contributing to SIGMA-PROBE

Добро пожаловать в сообщество SIGMA-PROBE! Мы рады вашему участию в развитии этой системы кибербезопасности enterprise-уровня.

## 🏗️ Архитектура Системы

SIGMA-PROBE построен на принципах модульной, событийно-ориентированной архитектуры:

```
src/
├── models/                 # Доменные модели данных
│   ├── core.py           # LogEvent, ActorProfile, ThreatCampaign
│   └── __init__.py
├── pipeline/              # Конвейер обработки
│   ├── base.py           # Базовые классы этапов
│   ├── ingestion.py      # Загрузка логов
│   ├── enrichment.py     # Обогащение признаками
│   ├── profiling.py      # Профилирование акторов
│   ├── detectors.py      # Детекторы угроз
│   ├── metadetector.py   # Cross-validation engine
│   ├── scoring.py        # Оценка угроз
│   ├── recommendations.py # Генерация рекомендаций
│   └── reporting.py      # Генерация отчетов
├── intelligence/          # Threat Intelligence
│   ├── ioc_manager.py    # Динамические IoC фиды
│   └── mitre_mapping.py  # MITRE ATT&CK маппинг
└── main.py               # Главный модуль
```

### Принципы Архитектуры

1. **Модульность**: Каждый компонент имеет четкую ответственность
2. **Событийность**: Компоненты общаются через shared context
3. **Расширяемость**: Легко добавлять новые детекторы и этапы
4. **Тестируемость**: Каждый компонент покрыт unit и behavioral тестами

## 🚀 Как Добавить Свой Детектор

### Шаг 1: Создание Детектора

Создайте новый файл в `src/pipeline/detectors.py`:

```python
class MyCustomDetector(BaseDetector):
    """Описание вашего детектора"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        # Инициализация параметров из config
        
    def detect(self, actors: List[ActorProfile], context: Dict[str, Any]) -> Dict[str, Any]:
        """Основная логика детекции"""
        for actor in actors:
            # Ваша логика анализа
            if self._detect_threat(actor):
                actor.tags.add('MY_CUSTOM_THREAT')
                self.add_evidence(actor, "threat_type", "description", confidence)
        
        return {'my_detector_summary': {...}}
    
    def _detect_threat(self, actor: ActorProfile) -> bool:
        """Внутренняя логика детекции"""
        # Ваша логика
        return True
```

### Шаг 2: Регистрация в Конфигурации

Добавьте детектор в `config.yaml`:

```yaml
detection:
  detectors:
    - MyCustomDetector
  mycustomdetector_detector:
    param1: value1
    param2: value2
```

### Шаг 3: Добавление MITRE Маппинга

В `src/intelligence/mitre_mapping.py` добавьте маппинг:

```python
def _initialize_mapping(self) -> Dict[str, List[str]]:
    return {
        # ... существующие маппинги ...
        'MY_CUSTOM_THREAT': ['T1190', 'T1595'],  # MITRE техники
    }
```

### Шаг 4: Создание Тестов

Создайте тесты в `tests/test_detectors.py`:

```python
def test_my_custom_detector():
    """Test MyCustomDetector functionality"""
    detector = MyCustomDetector(config)
    actors = [create_test_actor()]
    
    result = detector.detect(actors, {})
    
    assert 'MY_CUSTOM_THREAT' in actors[0].tags
    assert len(actors[0].evidence_trail) > 0
```

## 🧪 Запуск Тестов

### Установка зависимостей

```bash
pip install -r requirements.txt
```

### Запуск всех тестов

```bash
pytest tests/ -v
```

### Запуск конкретных тестов

```bash
# Unit тесты
pytest tests/test_detectors.py -v

# Behavioral тесты
pytest tests/test_lfi_scenario.py -v

# Coverage отчет
pytest tests/ --cov=src --cov-report=html
```

## 📋 Стандарты Кода

### Python Style Guide

Мы используем:
- **Black** для форматирования кода
- **Flake8** для проверки стиля
- **MyPy** для статической типизации

### Установка инструментов

```bash
pip install black flake8 mypy
```

### Проверка кода

```bash
# Форматирование
black src/ tests/

# Проверка стиля
flake8 src/ tests/

# Типизация
mypy src/
```

### Структура Коммитов

Используйте conventional commits:

```
feat: add new SQL injection detector
fix: resolve memory leak in FFTDetector
docs: update README with new features
test: add behavioral tests for API attacks
```

## 🔧 Настройка Окружения

### Требования

- Python 3.8+
- pip
- git

### Установка

```bash
git clone https://github.com/your-username/sigma-probe.git
cd sigma-probe
pip install -r requirements.txt
```

### Запуск

```bash
python src/main.py
```

## 🎯 Good First Issues

### Для Начинающих

1. **Добавить детектор для атак на API**
   - Создать `APIAttackDetector`
   - Добавить маппинг MITRE техник
   - Написать тесты

2. **Реализовать выгрузку отчетов в S3**
   - Создать `S3ReportingStage`
   - Добавить конфигурацию AWS
   - Написать интеграционные тесты

3. **Добавить поддержку новых форматов логов**
   - Создать парсер для Apache access logs
   - Добавить поддержку JSON логов
   - Написать тесты парсинга

### Для Опытных Разработчиков

1. **Реализовать Machine Learning детектор**
   - Интеграция с scikit-learn
   - Обучение на исторических данных
   - A/B тестирование с существующими детекторами

2. **Добавить Real-time обработку**
   - WebSocket интеграция
   - Streaming API
   - Real-time алерты

3. **Создать Dashboard**
   - Web интерфейс
   - Real-time визуализация
   - Интерактивные отчеты

## 📝 Pull Request Process

### Подготовка PR

1. **Создайте ветку**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Внесите изменения**
   - Следуйте стандартам кода
   - Добавьте тесты
   - Обновите документацию

3. **Проверьте код**
   ```bash
   black src/ tests/
   flake8 src/ tests/
   mypy src/
   pytest tests/ -v
   ```

4. **Создайте PR**
   - Опишите изменения
   - Укажите связанные issues
   - Добавьте скриншоты (если применимо)

### Шаблон PR

```markdown
## Описание
Краткое описание изменений

## Тип изменений
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Тестирование
- [ ] Unit тесты пройдены
- [ ] Behavioral тесты пройдены
- [ ] Новые тесты добавлены

## Дополнительная информация
Любая дополнительная информация
```

## 🤝 Code of Conduct

### Принципы

1. **Уважение**: Уважайте всех участников
2. **Конструктивность**: Критикуйте код, а не людей
3. **Открытость**: Будьте открыты к новым идеям
4. **Качество**: Стремитесь к высокому качеству кода

### Обратная связь

- Создавайте issues для багов и предложений
- Участвуйте в обсуждениях
- Помогайте другим участникам

## 📚 Полезные Ресурсы

### Документация

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [Pytest Documentation](https://docs.pytest.org/)

### Инструменты

- [Black Code Formatter](https://black.readthedocs.io/)
- [Flake8 Style Guide](http://flake8.pycqa.org/)
- [MyPy Type Checker](https://mypy.readthedocs.io/)

## 🏆 Признание

Все значимые контрибьюторы будут добавлены в:
- `CONTRIBUTORS.md`
- GitHub contributors
- Release notes

---

**Спасибо за ваш вклад в развитие SIGMA-PROBE! 🚀** 