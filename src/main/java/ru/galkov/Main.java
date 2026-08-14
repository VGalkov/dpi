package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.AdguardBlacklistSource;
import ru.galkov.blacklist_source.BlacklistSource;
import ru.galkov.blacklist_source.FileBlacklistSource;
import ru.galkov.blacklist_source.RknBlacklistSource;
import ru.galkov.llm.DnsAnomalyDetector;
import ru.galkov.servers.DnsServer;
import ru.galkov.servers.HttpProxyServer;
import ru.galkov.util.BlacklistLoader;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class Main {

    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private static DnsServer dnsServer;
    private static HttpProxyServer proxyServer;
    private static AppConfig config;
    private static BlacklistLoader blacklist;
    private static DnsAnomalyDetector dnsAnomalyDetector;

    public static void main(String[] args) {
        try {
            config = AppConfig.getInstance();

            List<BlacklistSource> sources = new ArrayList<>();

            addLocalFileSource(sources);
            addAdguardSource(sources);
            addMvpsSource(sources);
            addRknSource(sources);

            blacklist = new BlacklistLoader(sources);
            blacklist.load();

            dnsAnomalyDetector = new DnsAnomalyDetector();
            dnsAnomalyDetector.start();

            registerShutdownHook();

            startProxyServer();
            startDnsServer();

            logger.info("Система запущена");

        } catch (Exception e) {
            logger.error("Система не запущена", e);
            stopApplication();
            Runtime.getRuntime().exit(-1);
        }
    }

    private static void addLocalFileSource(List<BlacklistSource> sources) {
        if (!getConfig().getBoolean("blacklist.local.enabled")) {
            return;
        }

        FileBlacklistSource source = new FileBlacklistSource(
                new File(getConfig().get("blacklist.local.file"))
        );

        sources.add(source);
        logger.info("Источник LocalFile добавлен: {}", source);
    }

    private static void addAdguardSource(List<BlacklistSource> sources) {
        if (!getConfig().getBoolean("blacklist.adguard.enabled")) {
            return;
        }

        String url = getConfig().get("blacklist.adguard.url");

        AdguardBlacklistSource source = new AdguardBlacklistSource(
                url,
                getConfig().getInt("blacklist.adguard.connect-timeout"),
                getConfig().getInt("blacklist.adguard.read-timeout")
        );

        sources.add(source);
        logger.info("Источник AdGuard добавлен: {}", source);
    }

    private static void addMvpsSource(List<BlacklistSource> sources) {
        if (!getConfig().getBoolean("blacklist.mvps_hosts.enabled")) {
            return;
        }

        String url = getConfig().get("blacklist.mvps_hosts.url");

        AdguardBlacklistSource source = new AdguardBlacklistSource(
                url,
                getConfig().getInt("blacklist.adguard.connect-timeout"),
                getConfig().getInt("blacklist.adguard.read-timeout")
        );

        sources.add(source);
        logger.info("Источник MVPS Hosts добавлен: {}", source);
    }

    private static void addRknSource(List<BlacklistSource> sources) {
        if (!getConfig().getBoolean("blacklist.rkn.enabled")) {
            return;
        }

        RknBlacklistSource source = new RknBlacklistSource(
                Path.of(getConfig().get("blacklist.rkn.xml-file"))
        );

        sources.add(source);
        logger.info("Источник РКН добавлен: {}", source);
    }

    private static void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(
                new Thread(Main::stopApplication, "Dpi-Shutdown-Hook")
        );
    }

    private static synchronized void stopApplication() {
        logger.info("Начата штатная остановка системы");

        if (dnsAnomalyDetector != null) {
            try {
                dnsAnomalyDetector.stop();
            } catch (Exception e) {
                logger.error("Ошибка остановки DnsAnomalyDetector", e);
            }
        }

        if (proxyServer != null) {
            try {
                proxyServer.stop();
            } catch (Exception e) {
                logger.error("Ошибка остановки HTTP proxy", e);
            }
        }

        if (dnsServer != null) {
            try {
                dnsServer.stop();
            } catch (Exception e) {
                logger.error("Ошибка остановки DNS server", e);
            }
        }

        if (blacklist != null) {
            try {
                blacklist.close();
            } catch (Exception e) {
                logger.error("Ошибка остановки blacklist loader", e);
            }
        }

        logger.info("Штатная остановка системы завершена");
    }

    public static synchronized void startDnsServer() {
        if (dnsServer != null) {
            logger.info("DNS server уже инициализирован");
            return;
        }

        if (!config.getBoolean("dns.start")) {
            logger.info("DNS server отключён в application.properties");
            return;
        }

        dnsServer = new DnsServer(blacklist, dnsAnomalyDetector);

        Thread dnsThread = new Thread(
                dnsServer::run,
                "DnsServer-Main-Thread"
        );

        dnsThread.setDaemon(false);
        dnsThread.start();

        logger.info(
                "DNS server запущен в отдельном потоке на порту {}",
                getConfig().getInt("dns.local.port")
        );
    }

    public static synchronized void startProxyServer() {
        if (proxyServer != null) {
            logger.info("HTTP Proxy уже инициализирован");
            return;
        }

        if (!config.getBoolean("proxy.start")) {
            logger.info("HTTP Proxy отключён в application.properties");
            return;
        }

        int port = getConfig().getInt("proxy.local.port");

        logger.info(
                "Инициализация и запуск HTTP Proxy на порту {}",
                Optional.of(port)
        );

        proxyServer = new HttpProxyServer(port, blacklist);
        proxyServer.start();
    }

    public static AppConfig getConfig() {
        return config;
    }
}