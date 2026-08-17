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
        if (!getConfig().getBoolean("blacklist.local.enabled")) {
            return;
        }

        FileBlacklistSource source = new FileBlacklistSource(
                new File(getConfig().get("blacklist.local.file"))
        );

        sources.add(source);
        logger.info(LocaleUtil.getString("source_local_file_added"), source);
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
        logger.info(LocaleUtil.getString("source_adguard_added"), source);
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
        logger.info(LocaleUtil.getString("source_mvps_hosts_added"), source);
    }

    private static void addRknSource(List<BlacklistSource> sources) {
        if (!getConfig().getBoolean("blacklist.rkn.enabled")) {
            return;
        }

        RknBlacklistSource source = new RknBlacklistSource(
                Path.of(getConfig().get("blacklist.rkn.xml-file"))
        );

        sources.add(source);
        logger.info(LocaleUtil.getString("source_rkn_added"), source);
    }

    private static void registerShutdownHook() {
        Runtime.getRuntime().addShutdownHook(
                new Thread(Main::stopApplication, "Dpi-Shutdown-Hook")
        );
    }

    private static synchronized void stopApplication() {
        logger.info(LocaleUtil.getString("shutdown_started"));

        if (httpAnomalyDetector != null) {
            try {
                httpAnomalyDetector.stop();
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("error_stop_http_anomaly"), e);
            }
        }

        if (dnsAnomalyDetector != null) {
            try {
                dnsAnomalyDetector.stop();
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("error_stop_dns_anomaly"), e);
            }
        }

        if (proxyServer != null) {
            try {
                proxyServer.stop();
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("error_stop_http_proxy"), e);
            }
        }

        if (dnsServer != null) {
            try {
                dnsServer.stop();
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("error_stop_dns_server"), e);
            }
        }

        if (blacklist != null) {
            try {
                blacklist.close();
            } catch (Exception e) {
                logger.error(LocaleUtil.getString("error_stop_blacklist"), e);
            }
        }

        logger.info(LocaleUtil.getString("shutdown_completed"));
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

        Thread dnsThread = new Thread(
                dnsServer::run,
                "DnsServer-Main-Thread"
        );

        dnsThread.setDaemon(false);
        dnsThread.start();

        logger.info(
                LocaleUtil.getString("dns_server_started"),
                getConfig().getInt("dns.local.port")
        );
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

        int port = getConfig().getInt("proxy.local.port");

        logger.info(
                LocaleUtil.getString("http_proxy_init_start"),
                Optional.of(port)
        );

        proxyServer = new HttpProxyServer(port, blacklist, httpAnomalyDetector);
        proxyServer.start();
    }

    public static AppConfig getConfig() {
        return config;
    }
}