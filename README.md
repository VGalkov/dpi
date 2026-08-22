DPI-Proxy
Высокопроизводительный DPI-прокси с поддержкой DNS/HTTP/HTTPS, блокировкой по blacklist (RKN, AdGuard, MVPS) и детекцией аномалий на основе LLM.

Возможности
DNS Server — UDP/TCP, кэширование, rate limiting, blacklist, LLM anomaly detector.

HTTP/HTTPS Proxy — CONNECT, GET, POST, PUT, DELETE, SNI check, blacklist, LLM anomaly detector.

Blacklist — загрузка из файлов (local, RKN XML) и URL (AdGuard, MVPS), reload по расписанию.

LLM Anomaly Detector — анализ DNS/HTTP запросов на аномалии (circuit breaker, rate limiting).

Лимиты — maxConnections, maxConnectionsPerClient, maxHeaderBytes, maxBodyBytes, cleanup неактивных сокетов.

Быстрый старт
Требования
Java 21+

Maven 3.8+

LLM Studio (опционально, для anomaly detector)

Сборка
bash
mvn clean package
Запуск
bash
java -jar target/dpi-filter.jar
Конфигурация
application.properties:

text
# DNS Server
dns.start=true
dns.local.port=53
dns.thread.num=256
dns.timeout=3
dns.list=77.88.8.8,1.1.1.1,8.8.8.8

# HTTP Proxy
proxy.start=true
proxy.local.port=8888
proxy.max-connections=10000
proxy.max-connections-per-client=100

# Blacklist
blacklist.local.enabled=true
blacklist.adguard.enabled=true
blacklist.mvps_hosts.enabled=true
blacklist.rkn.enabled=false

# LLM Anomaly Detector
dns.anomaly-detector.enabled=false
http.anomaly-detector.enabled=false
Тесты
Запуск всех тестов
bash
mvn test
Запуск отдельных тестов
bash
# Юнит-тесты
mvn test -Dtest=DomainTrieTest
mvn test -Dtest=IpTrieTest
mvn test -Dtest=HostNormalizerTest
mvn test -Dtest=ProxyHandlerHelperTest

# Интеграционные тесты
mvn test -Dtest=BlacklistSnapshotTest
mvn test -Dtest=DnsServerIntegrationTest
mvn test -Dtest=HttpProxyServerIntegrationTest

# Стресс-тесты
mvn test -Dtest=MemoryLeakTest
mvn test -Dtest=SocketLeakTest
mvn test -Dtest=ConcurrencyStressTest
mvn test -Dtest=LimitExhaustionTest
Производительность
Сценарий	Ожидаемая производительность
DNS (UDP)	50,000–100,000 запросов/сек (на 4 ядрах)
DNS (TCP)	10,000–20,000 запросов/сек (на 4 ядрах)
HTTP Proxy	5,000–10,000 подключений/сек (на 4 ядрах)
HTTPS Proxy (CONNECT)	2,000–5,000 подключений/сек (на 4 ядрах)
Лимиты
Параметр	Значение
maxConnections	10,000 (по умолчанию)
maxConnectionsPerClient	100 (по умолчанию)
maxActiveSockets	20,000 (multiplier=2)
maxHeaderBytes	32,768 (32 KB)
maxBodyBytes	52,428,800 (50 MB)

