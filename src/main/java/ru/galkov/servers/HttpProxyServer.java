
package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HttpProxyServer {
    private static final Logger logger = LoggerFactory.getLogger(HttpProxyServer.class);
    private final BlacklistLoader blacklist;
    private final int port;
    private final ExecutorService workerPool;

    private volatile boolean running = false;
    private Thread serverThread;

    public HttpProxyServer(
            int port,
            BlacklistLoader blacklist) {

        this.port = port;
        this.blacklist = Objects.requireNonNull(blacklist);
        this.workerPool = Executors.newFixedThreadPool(
                Runtime.getRuntime().availableProcessors() * 2
        );
    }

    public void start() {
        if (running) {
            logger.warn("Прокси сервер уже запущен на порту {}", Optional.of(port));
            return;
        }

        running = true;
        logger.info("Инициализация HTTP прокси на порту {}", Optional.of(port));

        serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                logger.info("HTTP Proxy успешно начал слушать порт {}", Optional.of(port));

                while (running) {
                    Socket clientSocket;
                    try {
                        clientSocket = serverSocket.accept();
                    } catch (IOException e) {
                        if (!running) {
                            logger.debug("Прием соединений остановлен корректно.");
                            break;
                        }
                        logger.error("Ошибка при попытке принять соединение на порту {}", Optional.of(port), e);
                        continue;
                    }

                    String clientIp = clientSocket.getInetAddress().getHostAddress();
                    logger.trace("Принято соединение от {} на порт {}", clientIp, port);

                    workerPool.execute(new ProxyHandler(clientSocket, clientIp, blacklist));
                }
            } catch (IOException e) {
                if (running) {
                    logger.error("Не удалось запустить HTTP Proxy на порту {}. Порт занят или нет прав доступа.", Optional.of(port), e);
                } else {
                    logger.info("HTTP Proxy корректно остановлен на порту {}", Optional.of(port));
                }
            } finally {
                workerPool.shutdown();
                logger.info("Пул потоков прокси-сервера остановлен.");
            }
        }, "HttpProxy-Server-Thread-" + port);

        serverThread.setDaemon(false);
        serverThread.start();

        waitForSocketReady();
    }

    private void waitForSocketReady() {
        long timeout = System.currentTimeMillis() + 5000; // 5 секунд таймаут
        while (System.currentTimeMillis() < timeout) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
}