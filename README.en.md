DNS/HTTP Proxy Project... DPI
Purpose
The project implements a network service with two primary functions:

DNS forwarding over UDP and TCP;

HTTP/HTTPS proxy with CONNECT support;

blacklist checks for DNS and HTTP traffic;

request-rate and connection limits;

DNS/HTTP anomaly detection;

DNS-address and blacklist-snapshot caching;

aggregated operational logging.

The main purpose is to accept network requests, validate them against blocking rules, and forward permitted traffic to upstream servers.

Project Structure
text
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
Main Classes