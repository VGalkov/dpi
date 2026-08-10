
package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HttpProxyServer {
    private static final Logger logger = LoggerFactory.getLogger(HttpProxyServer.class);

    private final int port;
    private final ExecutorService workerPool;
    private final BlacklistLoader blacklist;

    private volatile boolean running = false;
    private Thread serverThread;

    public HttpProxyServer(int port) {
        this.port = port;
        this.workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
        this.blacklist = new BlacklistLoader();
    }

    public void start() {
        if (running) {
            logger.warn("Прокси сервер уже запущен на порту {}", port);
            return;
        }

        running = true;
        logger.info("Инициализация HTTP прокси на порту {}", port);

        serverThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(port)) {
                logger.info("HTTP Proxy успешно начал слушать порт {}", port);

                while (running) {
                    Socket clientSocket;
                    try {
                        clientSocket = serverSocket.accept();
                    } catch (IOException e) {
                        if (!running) {
                            logger.debug("Прием соединений остановлен корректно.");
                            break;
                        }
                        logger.error("Ошибка при попытке принять соединение на порту {}", port, e);
                        continue;
                    }

                    String clientIp = clientSocket.getInetAddress().getHostAddress();
                    logger.trace("Принято соединение от {} на порт {}", clientIp, port);

                    workerPool.execute(new ProxyHandler(clientSocket, clientIp, blacklist));
                }
            } catch (IOException e) {
                if (running) {
                    logger.error("Не удалось запустить HTTP Proxy на порту {}. Порт занят или нет прав доступа.", port, e);
                } else {
                    logger.info("HTTP Proxy корректно остановлен на порту {}", port);
                }
            } finally {
                workerPool.shutdown();
                logger.info("Пул потоков прокси-сервера остановлен.");
            }
        }, "HttpProxy-Server-Thread-" + port);

        serverThread.setDaemon(false); // ВАЖНО: JVM не завершится, пока жив этот поток
        serverThread.start();

        waitForSocketReady(port);
    }

    private void waitForSocketReady(int port) {
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