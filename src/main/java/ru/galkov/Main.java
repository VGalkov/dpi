package ru.galkov;

import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.servers.DnsServer;
import ru.galkov.servers.HttpProxyServer;

import java.io.IOException;
import java.util.Arrays;


/**
 * Galkov V A s0506777@yandex.ru
 */
public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private static DnsServer dnsServer;
    private static HttpProxyServer proxyServer;
    private static AppConfig config;

    public static void main(String[] args) {
        try {
            applicationInitialisation();
            startDnsServer();
            startProxyServer();
        } catch (Exception e) {
            logger.error(e.getMessage());
            Runtime.getRuntime().exit(-1);
        } finally {
            logger.info("Система запущена!");
        }
    }

    private static void applicationInitialisation() throws IOException {
        //порядок имеет значение.
        config = AppConfig.getInstance();
    }


    //Мы меняем настройки, но не все настройки перечитываются наново процессами.
    // Так что не все настройки будут обновляться без перезагрузки.
    private static void updateAppConf() {
        try {
            AppConfig.getInstance().reload();           // проверяем, изменились ли свойства.
            logger.info("Перегрузка конфигурации.({} сек.)", getConfig().get("Config.reload.timeout"));
        } catch (Exception e) {
            logger.warn("Ошибка при перезагрузке конфигурации: {}", e.getMessage());
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
                    proxyServer = new HttpProxyServer(getConfig().getInt("proxy.local.port"));
                    proxyServer.start();
                }
            }
        }
    }

    public static AppConfig getConfig() {
        return config;
    }

}

