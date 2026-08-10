package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class ProxyHandler implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(ProxyHandler.class);
    private final Socket clientSocket;
    private final String clientIp;
    private final BlacklistLoader blacklist;

    public ProxyHandler(Socket clientSocket, String clientIp, BlacklistLoader blacklist) {
        this.clientSocket = clientSocket;
        this.clientIp = clientIp;
        this.blacklist = blacklist;
    }

    @Override
    public void run() {
        try (InputStream clientIn = clientSocket.getInputStream();
             OutputStream clientOut = clientSocket.getOutputStream()) {

            byte[] buffer = new byte[8192];
            ByteArrayOutputStream headerBuffer = new ByteArrayOutputStream();
            boolean headersEnded = false;
            String hostHeader = null;
            String requestLine = null;

            // --- ШАГ 1: Чтение заголовков (до \r\n\r\n) ---
            while (!headersEnded) {
                int bytesRead = clientIn.read(buffer);
                if (bytesRead == -1) return; // Клиент закрыл соединение

                headerBuffer.write(buffer, 0, bytesRead);

                // Ищем конец заголовков в прочитанном буфере
                // Используем ISO_8859_1, так как HTTP заголовки текстовые ASCII
                String chunk = new String(buffer, 0, bytesRead, StandardCharsets.ISO_8859_1);

                // Проверка наличия маркера конца заголовков
                if (chunk.contains("\r\n\r\n")) {
                    headersEnded = true;
                }
            }

            byte[] fullHeaderBytes = headerBuffer.toByteArray();
            String fullHeaderText = new String(fullHeaderBytes, StandardCharsets.ISO_8859_1);

            // Парсим первую строку и заголовок Host
            String[] lines = fullHeaderText.split("\r\n");
            if (lines.length > 0) requestLine = lines[0];

            for (String line : lines) {
                if (line.toLowerCase().startsWith("host:")) {
                    hostHeader = line.substring(5).trim();
                    break;
                }
            }

            if (hostHeader == null) {
                logger.warn("HTTP [{}]: Отсутствует обязательный заголовок Host", clientIp);
                return; // Молча закрываем
            }

            logger.info("HTTP [{}] -> Запрос к: {}", clientIp, hostHeader);

            // --- ШАГ 2: ПРОВЕРКА BLACKLIST ---
            if (blacklist.isBlocked(hostHeader, clientIp)) {
                logger.info("HTTP [{}] <- ЗАБЛОКИРОВАНО (домен или IP в черном списке)", clientIp);
                // Молча закрываем соединение. Клиент получит таймаут.
                return;
            }

            // --- ШАГ 3: Подключение к целевому серверу ---
            int targetPort = 80;
            String targetHost = hostHeader;

            if (hostHeader.contains(":")) {
                try {
                    targetPort = Integer.parseInt(hostHeader.split(":")[1]);
                    targetHost = hostHeader.split(":")[0];
                } catch (NumberFormatException e) {
                    logger.warn("Неверный формат порта в Host: {}", hostHeader);
                }
            }

            Socket upstreamSocket;
            try {
                upstreamSocket = new Socket(targetHost, targetPort);
                logger.debug("HTTP [{}] -> Соединение с upstream: {}:{}", clientIp, targetHost, targetPort);
            } catch (IOException e) {
                logger.warn("HTTP [{}] -> Ошибка подключения к upstream {}:{}", clientIp, targetHost, targetPort);
                return;
            }

            try (OutputStream upstreamOut = upstreamSocket.getOutputStream();
                 InputStream upstreamIn = upstreamSocket.getInputStream()) {

                // Отправляем оригинальные заголовки на целевой сервер
                upstreamOut.write(fullHeaderBytes);
                upstreamOut.flush();

                // --- ШАГ 4: Двусторонняя ретрансляция (Relay) ---
                // Поток 1: Данные от Target -> Client
                Thread toClient = new Thread(() -> {
                    try {
                        byte[] buf = new byte[4096];
                        int len;
                        while ((len = upstreamIn.read(buf)) != -1) {
                            clientOut.write(buf, 0, len);
                            clientOut.flush();
                        }
                    } catch (IOException e) {
                        // Нормально, если клиент или сервер закрыли соединение
                        logger.trace("Relay (Upstream->Client) finished or error", e);
                    }
                });

                // Поток 2: Данные от Client -> Target (тело запроса, если есть)
                Thread toServer = new Thread(() -> {
                    try {
                        byte[] buf = new byte[4096];
                        int len;
                        while ((len = clientIn.read(buf)) != -1) {
                            upstreamOut.write(buf, 0, len);
                            upstreamOut.flush();
                        }
                    } catch (IOException e) {
                        logger.trace("Relay (Client->Upstream) finished or error", e);
                    }
                });

                toClient.start();
                toServer.start();

                toClient.join();
                toServer.join();

            } catch (Exception e) {
                logger.error("Ошибка ретрансляции данных", e);
            }

        } catch (Exception e) {
            logger.error("Критическая ошибка обработки клиента", e);
        } finally {
            try { if (!clientSocket.isClosed()) clientSocket.close(); } catch (IOException ignore) {}
        }
    }
}