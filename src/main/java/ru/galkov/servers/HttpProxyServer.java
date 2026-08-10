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

    public HttpProxyServer(int port) {
        this.port = port;
        // Размер пула: 2 потока на ядро процессора
        this.workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
        this.blacklist = new BlacklistLoader();
    }

    public void start() {
        logger.info("Запуск прозрачного HTTP прокси на порту {}", port);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (!Thread.currentThread().isInterrupted()) {
                Socket clientSocket = serverSocket.accept();
                String clientIp = clientSocket.getInetAddress().getHostAddress();

                logger.debug("TCP: Принято соединение от {}", clientIp);

                // Делегируем обработку в отдельный поток
                workerPool.execute(new ProxyHandler(clientSocket, clientIp, blacklist));
            }
        } catch (IOException e) {
            if (!Thread.currentThread().isInterrupted()) {
                logger.error("Ошибка запуска прокси-сервера", e);
            }
        } finally {
            workerPool.shutdown();
            logger.info("Прокси-сервер остановлен");
        }
    }

}