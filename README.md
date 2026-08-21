# Проект DNS/HTTP Proxy

## Назначение

Проект реализует сетевой сервис с двумя основными направлениями работы:

- DNS-форвардинг по UDP и TCP;
- HTTP/HTTPS proxy с поддержкой CONNECT;
- проверка DNS- и HTTP-трафика по blacklist;
- ограничение частоты запросов и количества соединений;
- анализ аномалий DNS/HTTP;
- кэширование DNS-адресов и blacklist snapshot;
- агрегированное логирование технических событий.

Основная цель — принимать сетевые запросы, проверять их по правилам блокировки и передавать разрешённый трафик upstream-серверам.

## Структура проекта

```text
ru.galkov
├── Main.java
├── servers
│   ├── DnsServer.java
│   ├── HttpProxyServer.java
│   ├── ProxyHandler.java
│   └── WorkerPool.java
├── util
│   ├── BlacklistLoader.java
│   ├── BlacklistRule.java
│   ├── BlacklistSnapshot.java
│   ├── ClientCounterMap.java
│   ├── DnsRateLimiter.java
│   ├── DnsServerHelper.java
│   ├── DomainTrie.java
│   ├── HostNormalizer.java
│   ├── IoUtil.java
│   ├── IpCidr.java
│   ├── LocaleUtil.java
│   ├── NamedThreadFactory.java
│   ├── ProxyHandlerHelper.java
│   └── RuleNormalizer.java
├── blacklist_source
│   ├── BlacklistSource.java
│   └── RknBlacklistSource.java
└── llm
    ├── DnsAnomalyDetector.java
    └── HttpAnomalyDetector.java
```

## Основные классы

### `DnsServer`

Основной DNS-сервер.

Отвечает за:

- UDP DNS listener;
- TCP DNS acceptor;
- приём и разбор DNS-запросов;
- ограничения по клиентам и активным сокетам;
- передачу запросов DNS upstream-resolver'ам;
- проверку query/response по blacklist;
- packet pool;
- DNS cache;
- очистку временных client counters;
- агрегированную статистику DNS-сервера.

Ключевые поля:

```java
private final ClientCounterMap queriesByClient;
private final ClientCounterMap activeUdpSockets;
private final ClientCounterMap tcpConnectionsByClient;
```

`ClientCounterMap` используется для потокобезопасного хранения счётчиков по IP-клиентам.

При изменении логики лимитов нужно проверять следующие места:

- увеличение счётчика клиента;
- decrement при завершении запроса;
- rollback при отказе worker pool;
- удаление нулевых счётчиков;
- очистку карт при превышении размера.

Нельзя создавать новый счётчик во время освобождения ресурса через `getOrCreate()`. Нужно передавать исходный `AtomicInteger`, который был увеличен при постановке задачи.

### `HttpProxyServer`

Listener HTTP proxy.

Отвечает за:

- открытие `ServerSocket`;
- приём TCP-соединений;
- ограничения общего количества соединений;
- ограничения соединений одного клиента;
- учёт активных сокетов;
- очистку idle sockets;
- передачу соединения в `WorkerPool`;
- запуск и остановку proxy-сервера.

Для per-client connection counters используется:

```java
private final ClientCounterMap connectionsByClient;
```

При изменении этого класса необходимо сохранять порядок освобождения:

1. уменьшить счётчик клиента;
2. удалить его, если значение стало нулевым;
3. освободить permit `Semaphore`;
4. закрыть socket при необходимости.

### `ProxyHandler`

Обрабатывает отдельное HTTP/HTTPS-соединение.

Отвечает за:

- чтение первой строки HTTP-запроса;
- разбор метода и target;
- обработку `CONNECT`;
- обработку обычных HTTP-методов;
- чтение HTTP-заголовков;
- ограничения размера заголовков и body;
- проверку host/IP по blacklist;
- SNI-проверку для CONNECT;
- передачу данных upstream;
- формирование HTTP ошибок;
- агрегирование локальной статистики ошибок.

При изменениях нельзя менять без отдельной проверки:

- коды HTTP-ответов;
- порядок blacklist-проверок;
- fail-closed поведение при отсутствии SNI;
- ограничения body;
- обработку chunked body;
- закрытие client и remote sockets.

### `WorkerPool`

Общий executor для DNS и HTTP задач.

Отвечает за:

- размер worker pool;
- размер очереди;
- rejection policy;
- создание worker threads;
- submit задач;
- shutdown;
- агрегирование rejected tasks.

Текущая важная особенность:

```text
конфигурационное имя CALLER_RUNS
```

может не соответствовать фактическому fallback-поведению, если используется custom handler, который отбрасывает задачу. Это отдельная функциональная тема и не должна исправляться автоматически вместе с безопасными refactoring-правками.

DNS и HTTP используют общий pool:

```text
DnsServer ───────┐
HttpProxyServer ─┼──> WorkerPool
```

Разделение pool'ов не выполняется в текущем проекте без отдельного нагрузочного анализа.

### `BlacklistLoader`

Загружает blacklist-правила из источников и формирует immutable snapshot.

Отвечает за:

- параллельную загрузку источников;
- нормализацию правил;
- обработку domain/IP/CIDR;
- ограничение числа правил;
- проверку memory limit;
- построение `DomainTrie`;
- периодический reload;
- агрегированное логирование статистики.

Логи внутри массовых циклов не добавлять. Счётчики и статистику нужно собирать, а выводить после обработки источников.

### `DnsRateLimiter`

Отдельный класс ограничения DNS-запросов.

Реализует token bucket по IP-клиенту:

- `requestsPerSecond`;
- `burst`;
- idle timeout клиента;
- периодическую очистку bucket'ов;
- ускоренную очистку при достижении количества запросов;
- агрегированную статистику rejected requests.

`DnsRateLimiter` был вынесен из `DnsServerHelper`, чтобы отделить самостоятельную функциональность rate limiting от DNS utility-методов.

### `DnsServerHelper`

DNS- и protocol-specific helper.

Отвечает за:

- извлечение имён из DNS-запросов;
- PTR IPv4/IPv6 parsing;
- blacklist-проверку query и response;
- формирование REFUSED response;
- TCP DNS framing;
- совместимые методы закрытия socket.

`DnsRateLimiter` здесь больше не должен дублироваться как вложенный класс.

### `ProxyHandlerHelper`

Helper для HTTP proxy и TLS CONNECT.

Отвечает за:

- чтение TLS ClientHello;
- извлечение SNI;
- разбор HTTP target;
- чтение HTTP lines;
- relay HTTP body;
- tunnel между client и remote socket.

Общие операции потокового I/O используют `IoUtil`:

```java
IoUtil.readExactly(...)
IoUtil.copy(...)
```

HTTP-specific операции остаются в этом классе:

- `relayChunked`;
- `relayFixed`;
- HTTP framing;
- TLS parsing;
- SNI extraction.

Их нельзя бездумно переносить в `IoUtil`, потому что они используют специальные лимиты и типы исключений.

## Утилитные классы

### `IoUtil`

Общие операции ввода-вывода и закрытия ресурсов.

Содержит:

```java
closeQuietly(Socket)
closeQuietly(ServerSocket)
closeQuietly(DatagramSocket)
readExactly(InputStream, int)
copy(InputStream, OutputStream, byte[])
copy(InputStream, OutputStream, byte[], long)
```

В `IoUtil` можно добавлять только действительно общие I/O-операции. Не следует помещать туда:

- client counters;
- DNS rate limiter;
- HTTP parsing;
- конфигурационные records;
- агрегированные runtime-метрики;
- общие серверные lifecycle-методы.

### `ClientCounterMap`

Потокобезопасная структура для счётчиков клиентов.

Основные операции:

```java
getOrCreate(String)
decrementAndRemoveIfZero(String, AtomicInteger)
removeZeroCounters()
removeOne()
size()
```

`AtomicInteger` используется намеренно: лимиты требуют точного атомарного increment/decrement. Заменять его на `LongAdder` для admission limits нельзя.

### `NamedThreadFactory`

Общая фабрика именованных потоков.

Используется для сохранения:

- имени потока;
- daemon/non-daemon режима;
- единого способа создания threads.

Текущие серверные потоки:

```text
DnsServer-TCP-Acceptor                 daemon=false
DnsServer-Cache-Cleanup-Thread         daemon=true
HttpProxy-Server-Thread-{port}         daemon=false
```

При замене thread factory daemon-режим менять нельзя.

### `HostNormalizer`

Нормализация host, domain, IP и host:port.

Отвечает за:

- нормализацию host;
- нормализацию IP;
- удаление trailing dot;
- разбор host/port;
- быструю проверку IP literal;
- совместимый wrapper для private IPv4-проверки.

Общая реализация проверки private/reserved IPv4 находится в `IpCidr`.

### `IpCidr`

Работа с CIDR и общей проверкой private/reserved IPv4.

Отвечает за:

- разбор CIDR;
- создание маски;
- проверку `contains`;
- кэширование адресов;
- общую проверку private/reserved IPv4.

`HostNormalizer.isPrivateIp(...)` оставлен как совместимый wrapper, чтобы не ломать существующие вызовы.

### `LocaleUtil`

Локализация сообщений.

Не использовать для хранения общих helper-методов. Сюда относятся только:

- загрузка ResourceBundle;
- выбор locale;
- кэширование шаблонов сообщений;
- подстановка параметров.

## Что уже реализовано

| Изменение | Состояние |
|---|---|
| Агрегированное логирование `BlacklistLoader` | Реализовано |
| Агрегированное логирование `ProxyHandler` | Реализовано |
| Агрегированное логирование `DnsServer` | Реализовано |
| Агрегированное логирование `HttpProxyServer` | Реализовано |
| Агрегирование rejected tasks в `WorkerPool` | Реализовано |
| Общий `IoUtil.closeQuietly` | Реализовано |
| `ClientCounterMap` | Реализовано |
| `NamedThreadFactory` | Реализовано |
| `readExactly` и raw `copy` в `IoUtil` | Реализовано |
| Вынос `DnsRateLimiter` из `DnsServerHelper` | Реализовано |
| Общая private/reserved IPv4-проверка в `IpCidr` | Реализовано |
| Очистка client maps через `ClientCounterMap` | Реализовано |

## Оставшиеся предложения

### 7. `executeSafely` в `WorkerPool`

Можно сократить повторяющийся `try/catch` вокруг `workerPool.execute` в `DnsServer` и `HttpProxyServer`.

Rollback ресурсов нельзя переносить внутрь `WorkerPool`, потому что DNS и HTTP освобождают разные объекты.

Файлы:

```text
WorkerPool.java
DnsServer.java
HttpProxyServer.java
```

### 8. `DatagramPacketPool`

Можно вынести управление packet pool из `DnsServer` в отдельный класс.

Ответственность нового класса:

- создание packet pool;
- выдача packet;
- возврат packet;
- создание временного packet при empty pool;
- статистика empty pool.

Файлы:

```text
DnsServer.java
DatagramPacketPool.java
```

Правка требует внимательно сохранить поведение при пустом pool.

### 12. HTTP raw relay

Можно ещё сильнее использовать `IoUtil.copy` для raw stream relay. `relayChunked` необходимо оставить в `ProxyHandlerHelper`, потому что это HTTP-specific parsing.

Файлы:

```text
IoUtil.java
ProxyHandlerHelper.java
ProxyHandler.java
```

### 20. `DnsRateLimiterFactory`

Можно вынести создание rate limiter из конструктора `DnsServer` в отдельную factory/config-функцию.

Это только структурная правка:

- алгоритм rate limiter не меняется;
- конфигурация не меняется;
- runtime-производительность почти не меняется.

Файлы:

```text
DnsServer.java
DnsRateLimiter.java
DnsRateLimiterFactory.java
```

## Что принято не делать

Следующие направления исключены из текущего плана:

- lifecycle helper для `HttpProxyServer`;
- `ProxyLimits`;
- `DnsServerConfig`;
- общий компонент runtime-метрик;
- общий helper для `submit`;
- исправление фактической политики `CALLER_RUNS`;
- разделение общего worker pool DNS и HTTP;
- перенос общих helper-методов в `LocaleUtil`;
- общий `AbstractServer`;
- большой `CommonServerUtils`.

## Правила безопасных изменений

1. Не менять порядок admission checks и rollback.
2. Не заменять `AtomicInteger` на `LongAdder` там, где проверяется лимит.
3. Не создавать новый client counter при освобождении ресурса.
4. Передавать исходный counter в асинхронную задачу.
5. Не логировать внутри массовых циклов.
6. Не переносить HTTP-specific parsing в `IoUtil`.
7. Не менять daemon-режим серверных потоков.
8. Не менять rejection policy без отдельного подтверждения.
9. Не менять типы исключений без проверки вызывающего кода.
10. После каждой правки проверять компиляцию и сравнивать поведение на тестовых сценариях.

## Проверка после изменений

Минимальный набор проверок:

- проект компилируется без warnings, связанных с изменёнными классами;
- DNS UDP-запрос проходит полный цикл;
- DNS TCP-запрос проходит полный цикл;
- HTTP GET проходит через proxy;
- HTTPS CONNECT с SNI проходит через proxy;
- заблокированный domain/IP возвращает отказ;
- превышение client limit освобождает счётчик;
- rejected worker task не оставляет permit или socket counter;
- завершение сервера закрывает listener и активные sockets;
- blacklist snapshot строится и reload работает;
- пустые client maps очищаются;
- logs не генерируются в массовых внутренних циклах.

## Текущий план

Оставшиеся разумные кандидаты:

1. `executeSafely` для `WorkerPool` без переноса rollback.
2. `DatagramPacketPool` для `DnsServer`.
3. Дополнительное использование `IoUtil.copy` для raw relay.
4. `DnsRateLimiterFactory` для упрощения создания rate limiter.

Приоритет следует отдавать правкам с низким риском изменения сетевого поведения.
