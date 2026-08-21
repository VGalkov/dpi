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
import ru.galkov.servers.WorkerPool;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.LocaleUtil;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    private static volatile DnsServer dnsServer;
    private static volatile HttpProxyServer proxyServer;
    private static volatile AppConfig config;
    private static volatile BlacklistLoader blacklist;
    private static volatile DnsAnomalyDetector dnsAnomalyDetector;
    private static volatile HttpAnomalyDetector httpAnomalyDetector;

    private static volatile boolean shutdownStarted;

    private Main() {}

    public static void main(String[] args) {
        try {
            config = AppConfig.getInstance();
            if (config == null) {
                logger.error(LocaleUtil.getString("main_config_null"));
                return;
            }

            List<BlacklistSource> sources = createBlacklistSources();

            if (sources.isEmpty()) {
                logger.error("No blacklist sources configured");
                return;
            }

            blacklist = new BlacklistLoader(sources);
            blacklist.load();

            dnsAnomalyDetector = new DnsAnomalyDetector();
            httpAnomalyDetector = new HttpAnomalyDetector();

            registerShutdownHook();

            startDetectors();

            startProxyServer();
            startDnsServer();

            logger.info(LocaleUtil.getString("system_started"));

        } catch (Exception e) {
            logger.error(LocaleUtil.getString("system_not_started"), e);
            stopApplication();
            Runtime.getRuntime().exit(1);
        }
    }

    private static List<BlacklistSource> createBlacklistSources() {
        List<BlacklistSource> sources = new ArrayList<>();

        addLocalFileSource(sources);
        addAdguardSource(sources);
        addMvpsSource(sources);
        addRknSource(sources);

        return sources;
    }

    private static void startDetectors() {
        if (dnsAnomalyDetector != null) dnsAnomalyDetector.start();
        if (httpAnomalyDetector != null) httpAnomalyDetector.start();

        logger.info(
                "Anomaly detectors started: dns={}, http={}",
                dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled(),
                httpAnomalyDetector != null && httpAnomalyDetector.isEnabled()
        );
    }

    private static void addLocalFileSource(List<BlacklistSource> sources) {
        if (config == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            return;
        }

        try {
            if (!config.getBoolean("blacklist.local.enabled")) return;
            String filePath = config.get("blacklist.local.file");
            FileBlacklistSource source = new FileBlacklistSource(new File(filePath));
            sources.add(source);
            logger.info(LocaleUtil.getString("source_local_file_added"), source);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("main_source_add_error"), "LocalFile", e);
        }
    }

    private static void addAdguardSource(List<BlacklistSource> sources) {
        if (config == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            return;
        }

        try {
            if (!config.getBoolean("blacklist.adguard.enabled")) return;

            AdguardBlacklistSource source = new AdguardBlacklistSource(
                    config.get("blacklist.adguard.url"),
                    config.getInt("blacklist.adguard.connect-timeout"),
                    config.getInt("blacklist.adguard.read-timeout")
            );

            sources.add(source);
            logger.info(LocaleUtil.getString("source_adguard_added"), source);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("main_source_add_error"), "AdGuard", e);
        }
    }

    private static void addMvpsSource(List<BlacklistSource> sources) {
        if (config == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            return;
        }

        try {
            if (!config.getBoolean("blacklist.mvps_hosts.enabled")) return;
            AdguardBlacklistSource source = new AdguardBlacklistSource(
                    config.get("blacklist.mvps_hosts.url"),
                    config.getInt("blacklist.mvps_hosts.connect-timeout"),
                    config.getInt("blacklist.mvps_hosts.read-timeout")
            );

            sources.add(source);
            logger.info(LocaleUtil.getString("source_mvps_hosts_added"), source);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("main_source_add_error"), "MVPS", e);
        }
    }

    private static void addRknSource(List<BlacklistSource> sources) {
        if (config == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            return;
        }

        try {
            if (!config.getBoolean("blacklist.rkn.enabled")) return;
            Path xmlPath = Path.of(config.get("blacklist.rkn.xml-file"));
            RknBlacklistSource source = new RknBlacklistSource(xmlPath);
            sources.add(source);
            logger.info(LocaleUtil.getString("source_rkn_added"), source);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("main_source_add_error"), "RKN", e);
        }
    }

    private static void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(Main::stopApplication, "Dpi-Shutdown-Hook"));
    }

    private static synchronized void stopApplication() {
        if (shutdownStarted) return;
        shutdownStarted = true;
        logger.info(LocaleUtil.getString("shutdown_started"));
        stopProxyServer();
        stopDnsServer();
        stopHttpAnomalyDetector();
        stopDnsAnomalyDetector();
        shutdownWorkerPool();
        closeBlacklist();
        logger.info(LocaleUtil.getString("shutdown_completed"));
    }

    private static void stopProxyServer() {
        HttpProxyServer server = proxyServer;
        if (server == null) return;

        try {
            server.stop();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("error_stop_http_proxy"), e);
        } finally {
            proxyServer = null;
        }
    }

    private static void stopDnsServer() {
        DnsServer server = dnsServer;
        if (server == null) return;

        try {
            server.stop();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("error_stop_dns_server"), e);
        } finally {
            dnsServer = null;
        }
    }

    private static void stopHttpAnomalyDetector() {
        HttpAnomalyDetector detector = httpAnomalyDetector;
        if (detector == null) return;
        try {
            detector.stop();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("error_stop_http_anomaly"), e);
        } finally {
            httpAnomalyDetector = null;
        }
    }

    private static void stopDnsAnomalyDetector() {
        DnsAnomalyDetector detector = dnsAnomalyDetector;
        if (detector == null) return;

        try {
            detector.stop();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("error_stop_dns_anomaly"), e);
        } finally {
            dnsAnomalyDetector = null;
        }
    }

    private static void shutdownWorkerPool() {
        try {
            WorkerPool.shutdown();
        } catch (Exception e) {
            logger.error("Failed to stop worker pool", e);
        }
    }

    private static void closeBlacklist() {
        BlacklistLoader loader = blacklist;
        if (loader == null) return;

        try {
            loader.close();
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("error_stop_blacklist"), e);
        } finally {
            blacklist = null;
        }
    }

    public static synchronized void startDnsServer() {
        if (dnsServer != null) {
            logger.info(LocaleUtil.getString("dns_server_already_initialized"));
            return;
        }

        if (config == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            return;
        }

        if (!config.getBoolean("dns.start")) {
            logger.info(LocaleUtil.getString("dns_server_disabled"));
            return;
        }

        if (blacklist == null) {
            logger.error(LocaleUtil.getString("main_blacklist_null"), "DNS");
            return;
        }

        if (dnsAnomalyDetector == null) {
            logger.error(
                    LocaleUtil.getString("main_anomaly_detector_null"),
                    "DnsAnomalyDetector");
            return;
        }

        try {
            DnsServer server = new DnsServer(blacklist, dnsAnomalyDetector);
            Thread dnsThread = new Thread(server::run, "DnsServer-Main-Thread");
            dnsThread.setDaemon(false);
            dnsThread.start();
            dnsServer = server;
            logger.info(LocaleUtil.getString("dns_server_started"), config.getInt("dns.local.port"));
        } catch (Exception e) {
            dnsServer = null;
            logger.error(LocaleUtil.getString("main_dns_server_start_error"), e);
        }
    }

    public static synchronized void startProxyServer() {
        if (proxyServer != null) {
            logger.info(LocaleUtil.getString("http_proxy_already_initialized"));
            return;
        }

        if (config == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            return;
        }

        if (!config.getBoolean("proxy.start")) {
            logger.info(LocaleUtil.getString("http_proxy_disabled"));
            return;
        }

        if (blacklist == null) {
            logger.error(LocaleUtil.getString("main_blacklist_null"), "HTTP Proxy");
            return;
        }

        if (httpAnomalyDetector == null) {
            logger.error(
                    LocaleUtil.getString("main_anomaly_detector_null"), "HttpAnomalyDetector");
            return;
        }

        try {
            int port = config.getInt("proxy.local.port");
            logger.info(LocaleUtil.getString("http_proxy_init_start"), port);
            HttpProxyServer server = new HttpProxyServer(port, blacklist, httpAnomalyDetector);
            server.start();
            proxyServer = server;
        } catch (Exception e) {
            proxyServer = null;
            logger.error(LocaleUtil.getString("main_proxy_server_start_error"), e);
        }
    }

    public static AppConfig getConfig() {
        AppConfig localConfig = config;

        if (localConfig == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            throw new IllegalStateException("AppConfig not initialized");
        }

        return localConfig;
    }
}