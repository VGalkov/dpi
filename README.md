📖 Общее описание
DPI-Proxy — это высокопроизводительный прокси-сервер для глубокой фильтрации сетевого трафика (Deep Packet Inspection) с поддержкой DNS, HTTP и HTTPS. Система предназначена для контроля и фильтрации интернет-трафика в корпоративных и домашних сетях.

Ключевые возможности
1. DNS Server
   Протоколы: UDP и TCP на порту 53

Кэширование: Встроенный DNS-кэш с настраиваемым TTL

Rate Limiting: Защита от DDoS и злоупотреблений

Blacklist: Блокировка доменов и IP-адресов

LLM Anomaly Detector: Анализ DNS-запросов на аномалии с помощью LLM(сейчас реализована только связка проекта с LM Studio, без серьёзного анализа)

2. HTTP/HTTPS Proxy
   Методы: CONNECT, GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH

SNI Check: Проверка Server Name Indication для HTTPS

Transparent Mode: Прозрачное проксирование для портов 80/443

Blacklist: Блокировка по доменам, IP и CIDR

LLM Anomaly Detector: Анализ HTTP-запросов на аномалии

3. Blacklist System
   Источники:

Локальные файлы (blacklist.txt)

RKN XML (реестр запрещённых сайтов)

AdGuard (списки рекламы и трекеров)

MVPS Hosts (универсальный blacklist)

Автообновление: Перезагрузка по расписанию

Лимиты: Защита от переполнения памяти

4. LLM Anomaly Detector
   Анализ: DNS и HTTP запросы

Circuit Breaker: Защита от сбоев LLM

Rate Limiting: Ограничение запросов к LLM

Trust Threshold: Порог доверия для блокировки

🚀 Быстрый старт
Требования
Java: 21 или выше

Maven: 3.8 или выше

ОС: Linux (рекомендуется), Windows, macOS

LLM Studio: Опционально (для anomaly detector)

Сборка
bash
# Клонирование репозитория
git clone https://github.com/your-repo/dpi-proxy.git
cd dpi-proxy

# Сборка проекта
mvn clean package

# Артефакт будет в target/dpi-filter.jar
Запуск
bash
# Базовый запуск
java -jar target/dpi-filter.jar

# С указанием пути к конфигу
java -Dconfig.path=/opt/dpi/application.properties -jar target/dpi-filter.jar

# В фоновом режиме (Linux)
nohup java -jar target/dpi-filter.jar > dpi.log 2>&1 &
⚙️ Конфигурация
application.properties
DNS Server
text
# Включить DNS сервер
dns.start=true

# Порт для прослушивания
dns.local.port=53

# Количество потоков обработки
dns.thread.num=256

# Таймаут запроса (секунды)
dns.timeout=3

# Upstream DNS серверы
dns.list=77.88.8.8,1.1.1.1,8.8.8.8,8.8.4.4

# Кэширование DNS
dns.dns-cache-ttl-minutes=10
dns.max-dns-cache-size=256

# Rate Limiting
dns.rate-limit.enabled=true
dns.rate-limit.requests-per-second=1000
dns.rate-limit.burst=2000
dns.rate-limit.client-idle-seconds=300

# Лимиты клиентов
dns.max-queries-by-client=5000
dns.max-tcp-connections-per-client=50
dns.max-active-tcp-sessions=500
HTTP/HTTPS Proxy
text
# Включить прокси
proxy.start=true

# Порты (прозрачный режим на 8080)
proxy.local.ports=8080,3128

# Лимиты подключений
proxy.max-connections=10000
proxy.max-connections-per-client=100
proxy.max-active-sockets-multiplier=100

# Таймауты
proxy.connect-timeout-millis=10000
proxy.client-read-timeout-millis=60000
proxy.remote-read-timeout-millis=60000

# Лимиты запросов
proxy.max-header-bytes=32768
proxy.max-body-bytes=104857600
proxy.stream-body-threshold=262144

# SNI проверка
proxy.block-on-sni-mismatch=false
Blacklist
text
# Локальный файл
blacklist.local.enabled=true
blacklist.local.file=blacklist.txt

# AdGuard
blacklist.adguard.enabled=true
blacklist.adguard.url=https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt
blacklist.adguard.connect-timeout=10000
blacklist.adguard.read-timeout=30000

# MVPS Hosts
blacklist.mvps_hosts.enabled=true
blacklist.mvps_hosts.url=https://winhelp2002.mvps.org/hosts.txt

# RKN (реестр запрещённых сайтов)
blacklist.rkn.enabled=true
blacklist.rkn.xml-file=dump.xml

# Лимиты
blacklist.max-rules-per-source=500000
blacklist.max-rules-rkn=10000000
blacklist.max-rules-total=10000000
blacklist.max-memory-mb=8192

# Автообновление
blacklist.reload.enabled=true
blacklist.reload.interval-seconds=3600
LLM Anomaly Detector
text
# DNS Anomaly Detector
dns.anomaly-detector.enabled=false
dns.anomaly-detector.llm-studio.url=http://localhost:1234/v1/chat/completions
dns.anomaly-detector.llm-studio.model=google/gemma-4-e2b
dns.anomaly-detector.trust-threshold=0.7
dns.anomaly-detector.max-requests-per-minute=2

# HTTP Anomaly Detector
http.anomaly-detector.enabled=false
http.anomaly-detector.llm-studio.url=http://localhost:1234/v1/chat/completions
http.anomaly-detector.trust-threshold=0.7
http.anomaly-detector.max-requests-per-minute=1