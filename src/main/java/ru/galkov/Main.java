package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.blacklist_source.AdguardBlacklistSource;
import ru.galkov.blacklist_source.BlacklistSource;
import ru.galkov.blacklist_source.FileBlacklistSource;
import ru.galkov.blacklist_source.RknBlacklistSource;
import ru.galkov.llm.DnsAnomalyDetector;
import ru.galkov.llm.HttpAnomalyDetector;
import ru.galkov.llm.LlmAnomalyDetector;
import ru.galkov.servers.CheckApiHandler;
import ru.galkov.servers.DnsServer;
import ru.galkov.servers.HttpProxyServer;
import ru.galkov.servers.WorkerPool;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.BlacklistSnapshot;
import ru.galkov.util.LocaleUtil;

import java.net.InetSocketAddress;
import java.nio.file.Files;
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
                logger.error(LocaleUtil.getString("no_blacklist_sources"));
                return;
            }

            blacklist = new BlacklistLoader(sources);
            blacklist.load();

            dnsAnomalyDetector = new DnsAnomalyDetector();
            httpAnomalyDetector = new HttpAnomalyDetector();
            LlmAnomalyDetector.initBlacklist(blacklist);

            startDnsServer();
            startProxyServer();
            startDetectors();
            registerShutdownHook();

            int checkApiPort = getConfig().getInt("check.api.port");
            startCheckApiServer(blacklist.snapshot(), checkApiPort);
            logger.info("Check API server started on port {}", checkApiPort);

            logger.info(LocaleUtil.getString("system_started"));
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("system_not_started"), e);
            stopApplication();
            Runtime.getRuntime().exit(1);
        }
    }

    private static void startCheckApiServer(BlacklistSnapshot snapshot, int port) {
        try {
            com.sun.net.httpserver.HttpServer server =
                    com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(port), 0);

            server.createContext("/", new CheckApiHandler(snapshot, port));
            server.setExecutor(null);
            server.start();

            logger.info("Check API HTTP server started on port {}", port);
        } catch (Exception e) {
            logger.error("Failed to start Check API server on port {}", port, e);
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
        logger.info("Anomaly detectors started: dns={}, http={}",
                dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled(),
                httpAnomalyDetector != null && httpAnomalyDetector.isEnabled());
    }

    private static void addLocalFileSource(List<BlacklistSource> sources) {
        if (config == null) {
            logger.error(LocaleUtil.getString("main_config_null"));
            return;
        }

        if (!config.getBoolean("blacklist.local.enabled")) {
            logger.info(LocaleUtil.getString("local_file_disabled"));
            return;
        }

        String pathStr = config.get("blacklist.local.file");

        if (pathStr.isBlank()) {
            logger.error(LocaleUtil.getString("local_file_path_not_set"));
            return;
        }

        Path path = Path.of(pathStr);

        if (!validateAndLogFile("blacklist.local.file", "blacklist.txt", path)) {
            return;
        }

        try {
            FileBlacklistSource source = new FileBlacklistSource(path.toFile());
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
                    config.getInt("blacklist.adguard.read-timeout"));
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
                    config.getInt("blacklist.mvps_hosts.read-timeout"));
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

        if (!config.getBoolean("blacklist.rkn.enabled")) {
            logger.info(LocaleUtil.getString("rkn_disabled"));
            return;
        }

        String pathStr = config.get("blacklist.rkn.xml-file");

        if (pathStr.isBlank()) {
            logger.error(LocaleUtil.getString("rkn_path_not_set"));
            return;
        }

        Path xmlPath = Path.of(pathStr);

        if (!validateAndLogFile("blacklist.rkn.xml-file", "dump.xml", xmlPath)) {
            return;
        }

        try {
            RknBlacklistSource source = new RknBlacklistSource(xmlPath);
            sources.add(source);
            logger.info(LocaleUtil.getString("source_rkn_added"), source);
        } catch (Exception e) {
            logger.error(LocaleUtil.getString("main_source_add_error"), "RKN", e);
            logger.warn("If the file exists but the error persists, check the XML format.");
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

    private static boolean validateAndLogFile(String configKey, String fileNameHint, Path path) {
        if (path == null) {
            logger.error("Path object is null for config key '{}'", configKey);
            return false;
        }

        Path absolutePath = path.toAbsolutePath();
        Path parentDir = path.getParent();
        String parentPathStr = (parentDir != null) ? parentDir.toAbsolutePath().toString() : "(Current folder)";

        logger.debug(LocaleUtil.getString("diag_header"), fileNameHint);
        logger.debug(LocaleUtil.getString("diag_config_path"), path);
        logger.debug(LocaleUtil.getString("diag_absolute_path"), absolutePath);
        logger.debug(LocaleUtil.getString("diag_parent_folder"), parentPathStr);

        boolean exists = Files.exists(path);
        boolean isFile = Files.isRegularFile(path);

        logger.debug(LocaleUtil.getString("diag_exists"), exists);
        logger.debug(LocaleUtil.getString("diag_is_file"), isFile);

        if (!exists || !isFile) {
            logger.error(LocaleUtil.getString("val_file_not_found"));
            logger.error(LocaleUtil.getString("val_folder_info"), parentPathStr);
            logger.error(LocaleUtil.getString("val_action_copy"), fileNameHint, parentPathStr);
            logger.error(LocaleUtil.getString("val_init_failed"), path, absolutePath);
            return false;
        }

        logger.debug(LocaleUtil.getString("diag_success"));
        return true;
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
        try { detector.stop(); } catch (Exception e) { logger.error(LocaleUtil.getString("error_stop_http_anomaly"), e); }
        finally { httpAnomalyDetector = null; }
    }

    private static void stopDnsAnomalyDetector() {
        DnsAnomalyDetector detector = dnsAnomalyDetector;
        if (detector == null) return;
        try { detector.stop(); } catch (Exception e) { logger.error(LocaleUtil.getString("error_stop_dns_anomaly"), e); }
        finally { dnsAnomalyDetector = null; }
    }

    private static void shutdownWorkerPool() {
        try { WorkerPool.shutdown(); } catch (Exception e) { logger.error(LocaleUtil.getString("failed_stop_worker_pool")); }
    }

    private static void closeBlacklist() {
        BlacklistLoader loader = blacklist;
        if (loader == null) return;
        try { loader.close(); } catch (Exception e) { logger.error(LocaleUtil.getString("error_stop_blacklist"), e); }
        finally { blacklist = null; }
    }

    public static synchronized void startDnsServer() {
        if (dnsServer != null) { logger.info(LocaleUtil.getString("dns_server_already_initialized")); return; }
        if (config == null) { logger.error(LocaleUtil.getString("main_config_null")); return; }
        if (!config.getBoolean("dns.start")) { logger.info(LocaleUtil.getString("dns_server_disabled")); return; }
        if (blacklist == null) { logger.error(LocaleUtil.getString("main_blacklist_null"), "DNS"); return; }
        if (dnsAnomalyDetector == null) { logger.error(LocaleUtil.getString("main_anomaly_detector_null"), "DnsAnomalyDetector"); return; }
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
        if (proxyServer != null) { logger.info(LocaleUtil.getString("http_proxy_already_initialized")); return; }
        if (config == null) { logger.error(LocaleUtil.getString("main_config_null")); return; }
        if (!config.getBoolean("proxy.start")) { logger.info(LocaleUtil.getString("http_proxy_disabled")); return; }
        if (blacklist == null) { logger.error(LocaleUtil.getString("main_blacklist_null"), "HTTP Proxy"); return; }
        if (httpAnomalyDetector == null) { logger.error(LocaleUtil.getString("main_anomaly_detector_null"), "HttpAnomalyDetector"); return; }
        try {
            logger.info(getConfig().getIntList("proxy.local.ports").toString(), getConfig().getIntList("proxy.local.ports"));
            proxyServer = new HttpProxyServer(getConfig().getIntList("proxy.local.ports"), blacklist, httpAnomalyDetector);
            proxyServer.start();
        } catch (Exception e) {
            proxyServer = null;
            logger.error(LocaleUtil.getString("main_proxy_server_start_error"), e);
        }
    }

    public static AppConfig getConfig() {
        AppConfig localConfig = config;
        if (localConfig == null) { logger.error(LocaleUtil.getString("main_config_null")); throw new IllegalStateException("AppConfig not initialized"); }
        return localConfig;
    }
}