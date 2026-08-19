package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.AdguardBlacklistSource;
import ru.galkov.blacklist_source.BlacklistSource;
import ru.galkov.blacklist_source.FileBlacklistSource;
import ru.galkov.blacklist_source.RknBlacklistSource;
import ru.galkov.llm.DnsAnomalyDetector;
import ru.galkov.llm.HttpAnomalyDetector;
import ru.galkov.servers.DnsServer;
import ru.galkov.servers.HttpProxyServer;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.LocaleUtil;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
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
    private static HttpAnomalyDetector httpAnomalyDetector;

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
            httpAnomalyDetector = new HttpAnomalyDetector();
            httpAnomalyDetector.start();

            registerShutdownHook();
            startProxyServer();
            startDnsServer();

            logger.info(LocaleUtil.getString("system_started"));
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("system_not_started"), e);
            stopApplication();
            Runtime.getRuntime().exit(-1);
        }
    }

    private static void addLocalFileSource(List<BlacklistSource> sources) {
        if (!config.getBoolean("blacklist.local.enabled")) return;
        FileBlacklistSource source = new FileBlacklistSource(new File(config.get("blacklist.local.file")));
        sources.add(source);
        logger.info(LocaleUtil.getString("source_local_file_added"), source);
    }

    private static void addAdguardSource(List<BlacklistSource> sources) {
        if (!config.getBoolean("blacklist.adguard.enabled")) return;
        AdguardBlacklistSource source = new AdguardBlacklistSource(
                config.get("blacklist.adguard.url"),
                config.getInt("blacklist.adguard.connect-timeout"),
                config.getInt("blacklist.adguard.read-timeout")
        );
        sources.add(source);
        logger.info(LocaleUtil.getString("source_adguard_added"), source);
    }

    private static void addMvpsSource(List<BlacklistSource> sources) {
        if (!config.getBoolean("blacklist.mvps_hosts.enabled")) return;
        AdguardBlacklistSource source = new AdguardBlacklistSource(
                config.get("blacklist.mvps_hosts.url"),
                config.getInt("blacklist.adguard.connect-timeout"),
                config.getInt("blacklist.adguard.read-timeout")
        );
        sources.add(source);
        logger.info(LocaleUtil.getString("source_mvps_hosts_added"), source);
    }

    private static void addRknSource(List<BlacklistSource> sources) {
        if (!config.getBoolean("blacklist.rkn.enabled")) return;
        RknBlacklistSource source = new RknBlacklistSource(Path.of(config.get("blacklist.rkn.xml-file")));
        sources.add(source);
        logger.info(LocaleUtil.getString("source_rkn_added"), source);
    }

    private static void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(Main::stopApplication, "Dpi-Shutdown-Hook"));
    }

    private static synchronized void stopApplication() {
        logger.info(LocaleUtil.getString("shutdown_started"));
        stop(httpAnomalyDetector, "error_stop_http_anomaly");
        stop(dnsAnomalyDetector, "error_stop_dns_anomaly");
        stop(proxyServer, "error_stop_http_proxy");
        stop(dnsServer, "error_stop_dns_server");
        close(blacklist, "error_stop_blacklist");
        logger.info(LocaleUtil.getString("shutdown_completed"));
    }

    private static void stop(Object obj, String errorKey) {
        if (obj == null) return;
        try {
            switch (obj) {
                case DnsAnomalyDetector anomalyDetector -> anomalyDetector.stop();
                case HttpAnomalyDetector anomalyDetector -> anomalyDetector.stop();
                case HttpProxyServer httpProxyServer -> httpProxyServer.stop();
                case DnsServer server -> server.stop();
                default -> {
                }
            }
        } catch (Exception e) {
            logger.error(LocaleUtil.getString(errorKey), e);
        }
    }

    private static void close(Object obj, String errorKey) {
        if (obj == null) return;
        try {
            if (obj instanceof BlacklistLoader) ((BlacklistLoader) obj).close();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString(errorKey), e);
        }
    }

    public static synchronized void startDnsServer() {
        if (dnsServer != null) {
            logger.info(LocaleUtil.getString("dns_server_already_initialized"));
            return;
        }
        if (!config.getBoolean("dns.start")) {
            logger.info(LocaleUtil.getString("dns_server_disabled"));
            return;
        }
        dnsServer = new DnsServer(blacklist, dnsAnomalyDetector);
        Thread dnsThread = new Thread(dnsServer::run, "DnsServer-Main-Thread");
        dnsThread.setDaemon(false);
        dnsThread.start();
        logger.info(LocaleUtil.getString("dns_server_started"), config.getInt("dns.local.port"));
    }

    public static synchronized void startProxyServer() {
        if (proxyServer != null) {
            logger.info(LocaleUtil.getString("http_proxy_already_initialized"));
            return;
        }
        if (!config.getBoolean("proxy.start")) {
            logger.info(LocaleUtil.getString("http_proxy_disabled"));
            return;
        }
        int port = config.getInt("proxy.local.port");
        logger.info(LocaleUtil.getString("http_proxy_init_start"), port);
        proxyServer = new HttpProxyServer(port, blacklist, httpAnomalyDetector);
        proxyServer.start();
    }

    public static AppConfig getConfig() {
        return config;
    }
}