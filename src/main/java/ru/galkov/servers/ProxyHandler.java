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

            while (!headersEnded) {
                int bytesRead = clientIn.read(buffer);
                if (bytesRead == -1) return;

                headerBuffer.write(buffer, 0, bytesRead);
                String chunk = new String(buffer, 0, bytesRead, StandardCharsets.ISO_8859_1);

                if (chunk.contains("\r\n\r\n"))
                    headersEnded = true;
            }

            byte[] fullHeaderBytes = headerBuffer.toByteArray();
            String fullHeaderText = new String(fullHeaderBytes, StandardCharsets.ISO_8859_1);

            String[] lines = fullHeaderText.split("\r\n");

            for (String line : lines) {
                if (line.toLowerCase().startsWith("host:")) {
                    hostHeader = line.substring(5).trim();
                    break;
                }
            }

            if (hostHeader == null) {
                logger.warn("HTTP [{}]: Отсутствует обязательный заголовок Host", clientIp);
                return;
            }

            logger.info("HTTP [{}] -> Запрос к: {}", clientIp, hostHeader);

            if (blacklist.isBlocked(hostHeader, clientIp)) {
                logger.info("HTTP [{}] <- ЗАБЛОКИРОВАНО (домен или IP в черном списке)", clientIp);
                return;
            }

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

                upstreamOut.write(fullHeaderBytes);
                upstreamOut.flush();

                Thread toClient = new Thread(() -> {
                    try {
                        byte[] buf = new byte[4096];
                        int len;
                        while ((len = upstreamIn.read(buf)) != -1) {
                            clientOut.write(buf, 0, len);
                            clientOut.flush();
                        }
                    } catch (IOException e) {
                        logger.trace("Relay (Upstream->Client) finished or error", e);
                    }
                });

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