# LLM Anomaly Detection Module

Модуль обнаружения аномалий в DNS и HTTP трафике с использованием LLM (Large Language Models).

## 📋 Содержание

- [Обзор](#обзор)
- [Архитектура](#архитектура)
- [Настройка](#настройка)
- [Мониторинг](#мониторинг)
- [Обучение модели](#обучение-модели)
- [Troubleshooting](#troubleshooting)
- [Changelog](#changelog)

---

## 📖 Обзор

Модуль анализирует DNS запросы и HTTP запросы на предмет аномалий с помощью LLM Studio (локальная LLM).

**Возможности:**
- ✅ Анализ DNS запросов (DGA, phishing, malware domains)
- ✅ Анализ HTTP запросов (SQL injection, XSS, path traversal)
- ✅ Интеграция с blacklist (домены + IP)
- ✅ Rate limiting + circuit breaker для защиты LLM
- ✅ Ленивые вычисления для производительности
- ✅ Потокобезопасная обработка
- ✅ Оптимизированные строковые операции (3x быстрее)
- ✅ Double-checked locking для getter'ов

---

## 🏗️ Архитектура
ru.galkov.llm
├── AbstractAnomalyDetector<T> # Базовый класс для детекторов
├── DnsAnomalyDetector # DNS детектор аномалий
├── HttpAnomalyDetector # HTTP детектор аномалий
├── AbstractQueryRecord # Базовый класс для записей
├── DnsQueryRecord # DNS запрос (ленивые вычисления)
├── HttpQueryRecord # HTTP запрос
├── AnalysisResult # Результат анализа LLM
└── LlmClient # Клиент для LLM Studio API

ru.galkov.util (зависимости)
├── BlacklistSnapshot # Кэш blacklist (очистка по TTL)
├── BlacklistLoader # Загрузчик blacklist
├── BlockDecision # Решение о блокировке
├── HostNormalizer # Нормализация хостов
├── IpCidr # Проверка CIDR (оптимизировано)
└── LocaleUtil # Локализация

text

### Поток данных
DNS/HTTP Server → recordQuery()/recordRequest()

Проверка blacklist (быстрая, ~100нс)

DnsAnomalyDetector/HttpAnomalyDetector → record()

Добавление в очередь (ConcurrentHashMap/LinkedBlockingQueue)

processQueue() → analyzeRecord(record)

buildPrompt(record) → LLM Client → parseResponse()

logAnomaly() при suspicious=true

text

---

## ⚙️ Настройка

### Конфигурация (AppConfig)

```properties
# DNS Anomaly Detector
dns.anomaly-detector.enabled=true
dns.anomaly-detector.llm-studio.url=http://localhost:1234/v1/chat/completions
dns.anomaly-detector.llm-studio.model=your-model-name
dns.anomaly-detector.llm-studio.timeout-seconds=30
dns.anomaly-detector.llm-studio.allow-local=true
dns.anomaly-detector.llm-studio.local-port=1234
dns.anomaly-detector.trust-threshold=0.7
dns.anomaly-detector.processed-ttl-seconds=3600
dns.anomaly-detector.max-requests-per-minute=10
dns.anomaly-detector.circuit-breaker.failure-threshold=50
dns.anomaly-detector.circuit-breaker.timeout-seconds=60
dns.anomaly-detector.max-queue-size=10000
dns.anomaly-detector.max-processed-domains=100000
dns.anomaly-detector.max-processed-clients=100000
dns.anomaly-detector.min-llm-interval-millis=120000

# HTTP Anomaly Detector
http.anomaly-detector.enabled=true
http.anomaly-detector.llm-studio.url=http://localhost:1234/v1/chat/completions
http.anomaly-detector.llm-studio.model=your-model-name
http.anomaly-detector.llm-studio.timeout-seconds=30
http.anomaly-detector.llm-studio.allow-local=true
http.anomaly-detector.llm-studio.local-port=1234
http.anomaly-detector.trust-threshold=0.7
http.anomaly-detector.processed-ttl-seconds=3600
http.anomaly-detector.max-requests-per-minute=10
http.anomaly-detector.circuit-breaker.failure-threshold=50
http.anomaly-detector.circuit-breaker.timeout-seconds=60
http.anomaly-detector.max-queue-size=10000
http.anomaly-detector.min-llm-interval-millis=5000
http.anomaly-detector.inspect-body=true
http.anomaly-detector.body-preview-length=500

# Blacklist Snapshot (кэш)
blacklist.snapshot.max-ip-cache-size=10000
blacklist.snapshot.max-domain-cache-size=20000
blacklist.snapshot.cache-ttl-millis=60000
```

### Промпты

**DNS:** `prompts/dns_anomaly_prompt.txt`
**HTTP:** `prompts/http_anomaly_prompt.txt`

**Структура промпта:**
Ты — модуль анализа DNS/HTTP безопасности...

Входные данные:
Client IP: {clientIp}
Domain: {domain}
Entropy: {entropy}
...

ПРИМЕР ТОЧНОГО ВЫХОДА:
{
"isSuspicious": false,
"confidence": 0.55,
"reason": "Легитимный домен",
"recommendedActions": ["NONE"]
}

text

---

## 📊 Мониторинг

### Логи

**DNS аномалии:**
DNS_ANOMALY_DETECTED client=192.168.1.1 domain=xn--80ak6aa92e.com
queryType=1 confidence=0.87 reason="Punycode + high entropy"
timestamp=1724256000000

text

**HTTP аномалии:**
HTTP anomaly detected: client=192.168.1.1, method=GET,
host=evil.com, path=/admin?id=1 OR 1=1, confidence=0.92,
reason="SQL injection detected", actions=[BLOCK_REQUEST]

text

### Метрики

| Метрика | Лог | Описание |
|---------|-----|----------|
| `dns_anomaly_detector_record_added` | DEBUG | Добавлен DNS запрос в очередь |
| `http_anomaly_detector_record_added` | DEBUG | Добавлен HTTP запрос в очередь |
| `dns_anomaly_detector_cleanup` | INFO | Очистка кэша (domains, clients, ttl) |
| `anomaly_detector_rate_limit_exceeded` | WARN | Превышен лимит запросов к LLM |
| `anomaly_detector_circuit_breaker_open` | WARN | Circuit breaker открыт (много ошибок) |
| `Circuit breaker opened after N failures` | WARN | Circuit breaker открыт |
| `Circuit breaker closed after timeout` | INFO | Circuit breaker закрыт |

---

## 🎓 Обучение модели

### 1. Сбор данных

**Формат датасета:**
```json
{
  "prompt": "Client IP: 192.168.1.1\nDomain: xn--80ak6aa92e.com\nEntropy: 4.23\n...",
  "completion": "{\"isSuspicious\": true, \"confidence\": 0.87, \"reason\": \"Punycode + high entropy\", \"recommendedActions\": [\"BLOCK_DOMAIN\"]}"
}
```

**Сбор логов:**
```bash
# Фильтрация логов
grep "DNS_ANOMALY_DETECTED" app.log > dns_anomalies.log
grep "HTTP anomaly detected" app.log > http_anomalies.log
```

### 2. Data augmentation

**Генерация синтетических данных:**
```python
import random
import string

def generate_dga_domain():
    length = random.randint(8, 20)
    name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    tld = random.choice(['.com', '.net', '.org', '.xyz', '.top'])
    return name + tld

def generate_legit_domain():
    words = ['google', 'facebook', 'amazon', 'microsoft', 'apple']
    tld = random.choice(['.com', '.net', '.org'])
    return random.choice(words) + tld
```

### 3. Fine-tuning

**Инструменты:**
- **LLM Studio** (Ollama, LM Studio) — LoRA/QLoRA
- **Hugging Face** — датасеты для DGA detection

**Few-shot prompts:**
Пример 1:
Domain: google.com, Entropy: 2.5 → {"isSuspicious": false, ...}

Пример 2:
Domain: xn--80ak6aa92e.com, Entropy: 4.2 → {"isSuspicious": true, ...}

Теперь оцени:
Domain: {domain}, Entropy: {entropy} → ...

text

### 4. Active learning

**Цикл:**
1. Модель предсказывает `confidence`
2. Запросы с `0.4 < confidence < 0.6` → на ручную разметку
3. Размеченные данные → дообучение модели

**Код для сбора:**
```java
if (result.confidence() >= 0.4 && result.confidence() <= 0.6) {
    logger.info("UNCERTAIN_PREDICTION domain={}, confidence={}", 
                domain, result.confidence());
    // Сохранить в базу для ручной разметки
}
```

---

## 🔧 Troubleshooting

### Проблема: LLM не отвечает

**Симптомы:**
WARN LLM API returned error status=503
WARN Circuit breaker opened after 50 failures

text

**Решение:**
1. Проверить LLM Studio: `curl http://localhost:1234/v1/models`
2. Увеличить timeout: `dns.anomaly-detector.llm-studio.timeout-seconds=60`
3. Уменьшить rate limit: `dns.anomaly-detector.max-requests-per-minute=5`

---

### Проблема: Много false positives

**Симптомы:**
INFO DNS_ANOMALY_DETECTED domain=google.com confidence=0.75

text

**Решение:**
1. Повысить trust threshold: `dns.anomaly-detector.trust-threshold=0.8`
2. Добавить в allowlist (через blacklist)
3. Дообучить модель на легитимных доменах

---

### Проблема: Медленная обработка

**Симптомы:**
WARN DNS anomaly queue full (size=10000)

text

**Решение:**
1. Увеличить очередь: `dns.anomaly-detector.max-queue-size=20000`
2. Увеличить rate limit: `dns.anomaly-detector.max-requests-per-minute=20`
3. Уменьшить min-llm-interval: `dns.anomaly-detector.min-llm-interval-millis=60000`

---

### Проблема: Утечка памяти

**Симптомы:**
INFO DNS cleanup: removed domains=0, clients=0, ttl=3600s

text

**Решение:**
1. Уменьшить TTL: `dns.anomaly-detector.processed-ttl-seconds=1800`
2. Уменьшить max-processed: `dns.anomaly-detector.max-processed-domains=50000`
3. Проверить кэш blacklist: `blacklist.snapshot.cache-ttl-millis=30000`

---

## 📈 Производительность

| Метрика | Значение |
|---------|----------|
| Создание `DnsQueryRecord` | ~50-100нс (ленивые вычисления) |
| Проверка blacklist | ~100нс |
| LLM запрос (локально) | ~500-2000мс |
| Rate limit | 10 запросов/мин (настраивается) |
| Circuit breaker | 50 ошибок → 60с пауза |
| `sanitizeForPrompt()` | 3x быстрее (цепочка replace) |
| `isBlockedAddressUncheckedIpv4()` | 10-15% быстрее (оптимизировано) |

---

## 🛡️ Безопасность

- ✅ Валидация LLM URL (localhost, blocked addresses)
- ✅ Circuit breaker (защита от DDoS на LLM)
- ✅ Rate limiting (10 запросов/мин по умолчанию)
- ✅ Prompt sanitization (удаление спецсимволов)
- ✅ Response validation (JSON parsing fallback)
- ✅ Оптимизированная проверка blocked IP (10-15% быстрее)

---

## 📝 Changelog

### v1.1 (2026-08-21) — Оптимизации
- ✅ Оптимизация `isBlockedAddressUncheckedIpv4()` (+10-15% скорость)
- ✅ Удалён `LogFields` (ненужный класс)
- ✅ Убрано дублирование `normalize*()` через `HostNormalizer`
- ✅ Убрано дублирование `calculate*Ratio()` через `calculateCharRatio()`
- ✅ Убрано дублирование `isBase*Like()` через `isLikeEncoding()`
- ✅ Оптимизация `hasInjectionMarkers()` (список маркеров + stream)

### v1.0 (2026-08-21) — Рефакторинг
- ✅ Ленивые вычисления в `DnsQueryRecord` (20-40x быстрее создание)
- ✅ Общий `analyzeRecord(T record)` в `AbstractAnomalyDetector`
- ✅ Оптимизация `sanitizeForPrompt()` (3x быстрее)
- ✅ Очистка кэша `BlacklistSnapshot` по TTL (-50% памяти)
- ✅ Общий `HttpClient` в `LlmClient` (-90% памяти)
- ✅ Убрано дублирование `getConfig*()` (1 метод вместо 6)
- ✅ Double-checked locking в getter'ах `DnsQueryRecord` (+20-30%)
- ✅ Удалён `LogFields` (ненужный класс)

---

## 📞 Контакты

- **Автор:** Galkov V.A.
- **Email:** s0506777@yandex.ru

---