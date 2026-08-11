package ru.galkov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.servers.*;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Galkov V A s0506777@yandex.ru
 * <p>
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
    static RknRequestSigner requestSigner;
    public static void main(String[] args) {
        try {
            config = AppConfig.getInstance();
            List<BlacklistSource> sources = new ArrayList<BlacklistSource>();


            if (getConfig().getBoolean("blacklist.local.enabled")) {
                FileBlacklistSource fileBlacklistSource = new FileBlacklistSource(new File(getConfig().get("blacklist.local.file")));
                sources.add(fileBlacklistSource);
                logger.info("Источник LocalFile добавлен: {}", fileBlacklistSource);
            }

            boolean adguardEnabled = getConfig().getBoolean("blacklist.adguard.enabled");
            String adguardUrl = getConfig().get("blacklist.adguard.url");

            logger.info("AdGuard blacklist: enabled={}, url={}", adguardEnabled, adguardUrl);

            if (adguardEnabled) {
                AdguardBlacklistSource adguardSource =
                        new AdguardBlacklistSource(
                                adguardUrl,
                                getConfig().getInt("blacklist.adguard.connect-timeout"),
                                getConfig().getInt("blacklist.adguard.read-timeout")
                        );

                sources.add(adguardSource);
                logger.info("Источник AdGuard добавлен: {}", adguardSource);
            }


            if (getConfig().getBoolean("blacklist.rkn.enabled")) {
                RknBlacklistSource rknBlacklistSource = new RknBlacklistSource(
                        getConfig().get("blacklist.rkn.endpoint"),
                        Path.of(getConfig().get("blacklist.rkn.request-file")), Path.of(getConfig().get("blacklist.rkn.signature-file")), getConfig().getBoolean("blacklist.rkn.emchd-enabled"), Path.of(getConfig().get("blacklist.rkn.emchd-file")), getConfig().get("blacklist.rkn.emchd-file-name"), Path.of(getConfig().get("blacklist.rkn.emchd-signature-file")), getConfig().getInt("blacklist.rkn.poll-interval-seconds"), getConfig().getInt("blacklist.rkn.poll-timeout-seconds"), getConfig().getInt("blacklist.rkn.connect-timeout"), getConfig().getInt("blacklist.rkn.read-timeout"), getConfig().get("rkn.operator-name"), getConfig().get("rkn.inn"), getConfig().get("rkn.ogrn"), getConfig().get("rkn.email"), getConfig().get("rkn.timezone"),
                        requestSigner
                );
                sources.add(rknBlacklistSource);
                logger.info("Источник РКН добавлен: {}", rknBlacklistSource);
            }

            blacklist = new BlacklistLoader(sources);
            blacklist.load();

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
                    logger.info("Инициализация и запуск HTTP Proxy на порту {}", Optional.of(port));
                    proxyServer = new HttpProxyServer(getConfig().getInt("proxy.local.port"), blacklist);
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

