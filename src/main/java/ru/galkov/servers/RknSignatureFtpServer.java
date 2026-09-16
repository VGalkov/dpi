package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.atomic.AtomicBoolean;

import static ru.galkov.Main.getConfig;

/**
 * Минималистичный FTP-сервер для приёма request.xml.sig.
 * Поддерживает PASV (пассивный режим) — совместим со стандартными FTP-клиентами.
 *
 * @author s0506777@yandex.ru Galkov V.A.
 */
public final class RknSignatureFtpServer {
    private static final Logger logger = LoggerFactory.getLogger(RknSignatureFtpServer.class);

    private final int port;
    private final Path saveDirectory;
    private final String allowedFileName;
    private final String username;
    private final String password;
    private final String allowedIp;
    private final AtomicBoolean running = new AtomicBoolean(false);

    private ServerSocket serverSocket;
    private Thread serverThread;

    private static final int SOCKET_TIMEOUT = 60_000;
    private static final int DATA_TIMEOUT   = 30_000;
    private static final int MAX_FILE_SIZE  = 10 * 1024 * 1024;
    private static final int BUFFER_SIZE    = 8_192;

    public RknSignatureFtpServer() {
        this.port = parsePositiveInt(getConfig().get("blacklist.rkn.remote.ftp.port"), 2121);

        String saveDirStr = getConfig().get("blacklist.rkn.remote.ftp.save-dir");
        if (saveDirStr == null || saveDirStr.isBlank()) {
            throw new IllegalArgumentException("blacklist.rkn.remote.ftp.save-dir не задан");
        }
        this.saveDirectory = Paths.get(saveDirStr);

        this.allowedFileName = getConfig().get("blacklist.rkn.remote.ftp.allowed-file");
        this.username = getConfig().get("blacklist.rkn.remote.ftp.username");
        this.password = getConfig().get("blacklist.rkn.remote.ftp.password");

        String ip = getConfig().get("blacklist.rkn.remote.ftp.allowed-ip");
        this.allowedIp = (ip != null) ? ip.trim() : "";

        try {
            Files.createDirectories(saveDirectory);
        } catch (IOException e) {
            throw new RuntimeException("Не удалось создать директорию: " + saveDirectory, e);
        }

        logger.info("RknSignatureFtpServer: port={}, saveDir={}, allowedFile={}, allowedIp={}",
                port, saveDirectory.toAbsolutePath(), allowedFileName,
                allowedIp.isBlank() ? "ANY" : allowedIp);
    }

    public void start() {
        if (!running.compareAndSet(false, true)) {
            logger.warn("RKN FTP Server уже запущен");
            return;
        }
        serverThread = new Thread(this::run, "RKN-FTP-Server-Thread");
        serverThread.setDaemon(true);
        serverThread.start();
        logger.info("RKN FTP Server запущен на порту {}", port);
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) return;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            logger.error("Ошибка закрытия серверного сокета", e);
        }
        if (serverThread != null) {
            serverThread.interrupt();
        }
        logger.info("RKN FTP Server остановлен");
    }

    private void run() {
        try (ServerSocket localServerSocket = new ServerSocket(port)) {
            serverSocket = localServerSocket;
            logger.info("RKN FTP Server слушает порт {}, каталог приёма: {}",
                    port, saveDirectory.toAbsolutePath());

            while (running.get()) {
                try {
                    Socket clientSocket = localServerSocket.accept();
                    clientSocket.setSoTimeout(SOCKET_TIMEOUT);
                    logger.info("Новое подключение: {}", clientSocket.getRemoteSocketAddress());
                    new Thread(() -> handleClient(clientSocket),
                            "RKN-FTP-Client-" + clientSocket.getPort()).start();
                } catch (IOException e) {
                    if (running.get()) {
                        logger.warn("Ошибка accept: {}", e.getMessage());
                    }
                }
            }
        } catch (IOException e) {
            if (running.get()) {
                logger.error("Критическая ошибка FTP сервера: {}", e.getMessage(), e);
            }
        } finally {
            running.set(false);
        }
    }

    private void handleClient(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();

        // Фильтр по IP
        if (!allowedIp.isBlank() && !allowedIp.equals(clientIp)) {
            logger.warn("Подключение отклонено (IP не разрешён): {}", clientIp);
            try (Socket s = clientSocket;
                 PrintWriter w = new PrintWriter(s.getOutputStream(), true)) {
                w.println("421 Connection refused: IP not allowed");
            } catch (IOException ignored) {}
            return;
        }

        try (Socket socket = clientSocket;
             BufferedReader reader = new BufferedReader(
                     new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
             PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {

            writer.println("220 RKN Signature FTP Server Ready");

            String userName = null;
            boolean authenticated = false;
            ServerSocket dataServerSocket = null;

            while (running.get()) {
                String command = reader.readLine();
                if (command == null) break;

                logger.info("CMD от {}: {}", clientIp, command);

                String[] parts = command.split(" ", 2);
                String cmd = parts[0].toUpperCase();

                switch (cmd) {
                    case "USER":
                        userName = parts.length > 1 ? parts[1].trim() : "";
                        writer.println("331 Password required for " + userName);
                        break;

                    case "PASS":
                        String pass = parts.length > 1 ? parts[1].trim() : "";
                        if (this.username.equals(userName) && this.password.equals(pass)) {
                            authenticated = true;
                            writer.println("230 Login successful");
                            logger.info("Аутентификация успешна: {}@{}", userName, clientIp);
                        } else {
                            writer.println("530 Login incorrect");
                            logger.warn("Аутентификация неудачна: {}@{}", userName, clientIp);
                        }
                        break;

                    case "TYPE":
                        writer.println("200 Type set to I");
                        break;

                    case "PASV":
                        if (!authenticated) {
                            writer.println("530 Not authenticated");
                            break;
                        }
                        if (dataServerSocket != null && !dataServerSocket.isClosed()) {
                            try { dataServerSocket.close(); } catch (IOException ignored) {}
                        }
                        try {
                            dataServerSocket = new ServerSocket(0);
                            dataServerSocket.setSoTimeout(DATA_TIMEOUT);
                            InetAddress addr = socket.getLocalAddress();
                            int dataPort = dataServerSocket.getLocalPort();
                            String ipStr = addr.getHostAddress().replace(".", ",");
                            int p1 = dataPort / 256;
                            int p2 = dataPort % 256;
                            writer.println("227 Entering Passive Mode (" + ipStr + "," + p1 + "," + p2 + ")");
                            logger.info("PASV: data-порт {} для {}", dataPort, clientIp);
                        } catch (IOException e) {
                            writer.println("425 Cannot open data connection");
                            logger.error("Ошибка открытия data socket: {}", e.getMessage());
                        }
                        break;

                    case "STOR":
                        if (!authenticated) {
                            writer.println("530 Not authenticated");
                            break;
                        }
                        String fileName = parts.length > 1 ? parts[1].trim() : "";
                        handleStoreFile(writer, dataServerSocket, fileName, clientIp);
                        // Закрываем data socket после передачи
                        if (dataServerSocket != null && !dataServerSocket.isClosed()) {
                            try { dataServerSocket.close(); } catch (IOException ignored) {}
                        }
                        dataServerSocket = null;
                        break;

                    case "QUIT":
                        writer.println("221 Goodbye");
                        if (dataServerSocket != null) {
                            try { dataServerSocket.close(); } catch (IOException ignored) {}
                        }
                        return;

                    case "NOOP":
                        writer.println("200 NOOP");
                        break;

                    case "SYST":
                        writer.println("215 UNIX Type: L8");
                        break;

                    case "CWD":
                        writer.println("250 OK");
                        break;

                    case "PWD":
                        writer.println("257 \"/\"");
                        break;

                    case "OPTS":
                        writer.println("200 OK");
                        break;

                    case "REST":
                        writer.println("350 Ready to restart");
                        break;

                    case "SIZE":
                        writer.println("550 Not available");
                        break;

                    default:
                        writer.println("502 Command not implemented: " + cmd);
                        logger.debug("Неизвестная команда: {} от {}", cmd, clientIp);
                }
            }

            if (dataServerSocket != null) {
                try { dataServerSocket.close(); } catch (IOException ignored) {}
            }

        } catch (IOException e) {
            logger.warn("Ошибка обработки клиента {}: {}", clientIp, e.getMessage());
        }
    }

    /**
     * Приём файла через data-соединение (PASV).
     */
    private void handleStoreFile(PrintWriter writer, ServerSocket dataServerSocket,
                                 String fileName, String clientIp) {
        logger.info("STOR: {} от {}", fileName, clientIp);

        if (!allowedFileName.equals(fileName)) {
            writer.println("553 File name not allowed. Only " + allowedFileName + " is accepted");
            logger.warn("Отклонён файл: {} (разрешён только {})", fileName, allowedFileName);
            return;
        }

        if (dataServerSocket == null || dataServerSocket.isClosed()) {
            writer.println("425 Use PASV first");
            logger.warn("STOR без PASV от {}", clientIp);
            return;
        }

        writer.println("150 Ok to send data");

        try (Socket dataSocket = dataServerSocket.accept()) {
            dataSocket.setSoTimeout(DATA_TIMEOUT);
            Path outputPath = saveDirectory.resolve(fileName);
            long totalBytes;

            try (OutputStream fos = Files.newOutputStream(outputPath,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
                 InputStream dataIn = dataSocket.getInputStream()) {

                byte[] buffer = new byte[BUFFER_SIZE];
                int bytesRead;
                totalBytes = 0;

                while ((bytesRead = dataIn.read(buffer)) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    totalBytes += bytesRead;
                    if (totalBytes > MAX_FILE_SIZE) {
                        logger.warn("Превышен лимит размера файла ({} байт) от {}", MAX_FILE_SIZE, clientIp);
                        writer.println("550 File too large");
                        return;
                    }
                }
            }

            writer.println("226 Transfer complete. Received " + totalBytes + " bytes");
            logger.info("Файл сохранён: {} ({} байт) от {}", outputPath.toAbsolutePath(), totalBytes, clientIp);

        } catch (IOException e) {
            writer.println("426 Transfer failed: " + e.getMessage());
            logger.error("Ошибка передачи файла от {}: {}", clientIp, e.getMessage());
        }
    }

    private int parsePositiveInt(String value, int defaultValue) {
        if (value == null || value.isBlank()) return defaultValue;
        try {
            int parsed = Integer.parseInt(value.trim());
            return parsed > 0 ? parsed : defaultValue;
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }
}