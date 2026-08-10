package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    public static void main(String[] args) {
        try {
            config = AppConfig.getInstance();
            startProxyServer();
            startDnsServer();
        } catch (Exception e) {
            logger.error(e.getMessage());
            Runtime.getRuntime().exit(-1);
        } finally {
            logger.info("Система запущена!");
        }
    }

    public static synchronized void startDnsServer() {
        if (dnsServer == null && config.getBoolean("dns.start")) {
            synchronized (DnsServer.class) {
                if (dnsServer == null) {
                    dnsServer = new DnsServer();
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
                    proxyServer = new HttpProxyServer(port);
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

