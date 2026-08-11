package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.servers.BlacklistLoader;
import ru.galkov.servers.DnsServer;
import ru.galkov.servers.HttpProxyServer;


/**
 * Galkov V A s0506777@yandex.ru
 *
 * nslookup.exe www.ssr.ru 10.0.3.10
 * .\curl -v -x http://127.0.0.1:8888 https://www.google.com
 * .\curl -v -x http://127.0.0.1:8888 http://example.com
 */
public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private static DnsServer dnsServer;
    private static HttpProxyServer proxyServer;
    private static AppConfig config;
    private static BlacklistLoader blacklist;
    public static void main(String[] args) {
        try {
            config = AppConfig.getInstance();
            blacklist = new BlacklistLoader();

            startProxyServer();
            startDnsServer();

            logger.info("Система запущена!");
        } catch (Exception e) {
            logger.error("Система не запущена", e);
            Runtime.getRuntime().exit(-1);
        }
    }

    public static synchronized void startDnsServer() {
        if (dnsServer == null && config.getBoolean("dns.start")) {
            synchronized (DnsServer.class) {
                if (dnsServer == null) {
                    dnsServer = new DnsServer(blacklist);
                    dnsServer.run();
                }
            }
        }
    }

    public static synchronized void startProxyServer() {
        if (proxyServer == null && config.getBoolean("proxy.start")) {
            synchronized (HttpProxyServer.class) {
                if (proxyServer == null) {
                    int port = getConfig().getInt("proxy.local.port");
                    logger.info("Инициализация и запуск HTTP Proxy на порту {}", port);
                    proxyServer = new HttpProxyServer(
                            getConfig().getInt("proxy.local.port"),
                            blacklist
                    );
                    proxyServer.start();
                }
            }
        } else if (proxyServer != null) {
            logger.info("HTTP Proxy уже инициализирован");
        }
    }

    public static AppConfig getConfig() {
        return config;
    }

}

