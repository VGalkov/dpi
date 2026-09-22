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
import java.util.concurrent.atomic.AtomicInteger;

import static ru.galkov.Main.getConfig;

/**
 * Минималистичный FTP-сервер для приёма request.xml.sig.
 * @author s0506777@yandex.ru Galkov V.A.
 */
public final class RknSignatureFtpServer {
    private static final Logger logger = LoggerFactory.getLogger(RknSignatureFtpServer.class);

    private final int port;
    private final Path saveDirectory;
    private final String allowedFileName1;
    private final String allowedFileName2;
    private final String username;
    private final String password;
    private final String allowedIp;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicInteger activeConnections = new AtomicInteger(0);

    private ServerSocket serverSocket;
    private Thread serverThread;

    private static final int SOCKET_TIMEOUT = 60_000;
    private static final int DATA_TIMEOUT   = 30_000;
    private static final int MAX_FILE_SIZE  = 10 * 1024 * 1024;
    private static final int BUFFER_SIZE    = 128 * 1024;  // ✅ 128 KB
    private static final int MAX_CONNECTIONS = 3;          // ✅ Лимит подключений

    // BOM (Byte Order Mark) — невидимый символ U+FEFF, который некоторые клиенты
    // добавляют в начало потока при использовании UTF-8
    private static final String BOM = "\uFEFF";

    public RknSignatureFtpServer() {
        this.port = parsePositiveInt(getConfig().get("blacklist.rkn.remote.ftp.port"), 2121);

        String saveDirStr = getConfig().get("blacklist.rkn.remote.ftp.save-dir");
        if (saveDirStr == null || saveDirStr.isBlank()) {
            throw new IllegalArgumentException("blacklist.rkn.remote.ftp.save-dir не задан");
        }
        this.saveDirectory = Paths.get(saveDirStr);

        this.allowedFileName1 = getConfig().get("blacklist.rkn.remote.ftp.allowed-file1");
        this.allowedFileName2 = getConfig().get("blacklist.rkn.remote.ftp.allowed-file2");
        this.username = getConfig().get("blacklist.rkn.remote.ftp.username");
        this.password = getConfig().get("blacklist.rkn.remote.ftp.password");

        String ip = getConfig().get("blacklist.rkn.remote.ftp.allowed-ip");
        this.allowedIp = (ip != null) ? ip.trim() : "";

        try {
            Files.createDirectories(saveDirectory);
        } catch (IOException e) {
            throw new RuntimeException("Не удалось создать директорию: " + saveDirectory, e);
        }

        logger.info("RknSignatureFtpServer: port={}, saveDir={}, allowedFile={} {}, allowedIp={}, maxConnections={}",
                port, saveDirectory.toAbsolutePath(), allowedFileName1, allowedFileName2,
                allowedIp.isBlank() ? "ANY" : allowedIp, MAX_CONNECTIONS);
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
            try {
                serverThread.join(5000);  // ✅ Ждём завершения потока
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
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

                    // ✅ Проверка лимита подключений
                    if (activeConnections.get() >= MAX_CONNECTIONS) {
                        try (PrintWriter w = new PrintWriter(clientSocket.getOutputStream(), true)) {
                            w.println("421 Too many connections");
                        } catch (IOException ignored) {}
                        clientSocket.close();
                        logger.debug("Превышен лимит подключений ({}), отклонено", MAX_CONNECTIONS);
                        continue;
                    }

                    clientSocket.setSoTimeout(SOCKET_TIMEOUT);
                    logger.debug("Новое подключение: remote={}, local={}",
                            clientSocket.getRemoteSocketAddress(),
                            clientSocket.getLocalSocketAddress());
                    new Thread(() -> handleClient(clientSocket),
                            "RKN-FTP-Client-" + clientSocket.getPort()).start();
                } catch (IOException e) {
                    if (running.get()) {
                        logger.debug("Ошибка accept: {}", e.getMessage());
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

    /**
     * Удаление BOM и лишних пробелов из команды.
     * Некоторые клиенты (например PowerShell с UTF-8) добавляют BOM в начало потока.
     */
    private static String sanitizeCommand(String command) {
        if (command == null) return null;
        // Удаляем BOM из начала строки
        while (command.startsWith(BOM)) {
            command = command.substring(BOM.length());
        }
        return command.trim();
    }

    private void handleClient(Socket clientSocket) {
        String clientIp = clientSocket.getInetAddress().getHostAddress();

        // ✅ Счётчик подключений
        activeConnections.incrementAndGet();
        try {

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
                 PrintWriter writer = new PrintWriter(
                         new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true)) {

                logger.debug("[{}] Отправлен: 220 RKN Signature FTP Server Ready", clientIp);
                writer.println("220 RKN Signature FTP Server Ready");

                String userName = null;
                boolean authenticated = false;
                ServerSocket dataServerSocket = null;

                try {  // ✅ Блок для гарантированного закрытия dataServerSocket
                    while (running.get()) {
                        String command = reader.readLine();
                        if (command == null) {
                            logger.debug("[{}] Клиент закрыл соединение (readLine=null)", clientIp);
                            break;
                        }

                        // Удаление BOM и trim
                        command = sanitizeCommand(command);

                        logger.debug("[{}] Получена команда: {}", clientIp, command);

                        String[] parts = command.split(" ", 2);
                        String cmd = parts[0].toUpperCase();

                        switch (cmd) {
                            case "USER":
                                userName = parts.length > 1 ? parts[1].trim() : "";
                                logger.debug("[{}] Отправлен: 331 Password required for {}", clientIp, userName);
                                writer.println("331 Password required for " + userName);
                                break;

                            case "PASS":
                                String pass = parts.length > 1 ? parts[1].trim() : "";
                                if (this.username.equals(userName) && this.password.equals(pass)) {
                                    authenticated = true;
                                    logger.debug("[{}] Отправлен: 230 Login successful", clientIp);
                                    writer.println("230 Login successful");
                                    logger.info("Аутентификация успешна: {}@{}", userName, clientIp);
                                } else {
                                    logger.debug("[{}] Отправлен: 530 Login incorrect", clientIp);
                                    writer.println("530 Login incorrect");
                                    logger.warn("Аутентификация неудачна: {}@{}", userName, clientIp);
                                }
                                break;

                            case "TYPE":
                                logger.debug("[{}] Отправлен: 200 Type set to I", clientIp);
                                writer.println("200 Type set to I");
                                break;

                            case "PASV":
                                if (!authenticated) {
                                    logger.debug("[{}] Отправлен: 530 Not authenticated (PASV)", clientIp);
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
                                    String pasvResp = "227 Entering Passive Mode (" + ipStr + "," + p1 + "," + p2 + ")";
                                    logger.debug("[{}] Отправлен: {}", clientIp, pasvResp);
                                    writer.println(pasvResp);
                                    logger.debug("[{}] Data socket открыт на порту {}", clientIp, dataPort);
                                } catch (IOException e) {
                                    logger.debug("[{}] Отправлен: 425 Cannot open data connection ({})", clientIp, e.getMessage());
                                    writer.println("425 Cannot open data connection");
                                    logger.error("Ошибка открытия data socket: {}", e.getMessage());
                                }
                                break;

                            case "STOR":
                                if (!authenticated) {
                                    logger.debug("[{}] Отправлен: 530 Not authenticated (STOR)", clientIp);
                                    writer.println("530 Not authenticated");
                                    break;
                                }
                                String fileName = parts.length > 1 ? parts[1].trim() : "";
                                handleStoreFile(writer, dataServerSocket, fileName, clientIp);
                                if (dataServerSocket != null && !dataServerSocket.isClosed()) {
                                    try { dataServerSocket.close(); } catch (IOException ignored) {}
                                }
                                dataServerSocket = null;
                                break;

                            case "QUIT":
                                logger.debug("[{}] Отправлен: 221 Goodbye", clientIp);
                                writer.println("221 Goodbye");
                                if (dataServerSocket != null) {
                                    try { dataServerSocket.close(); } catch (IOException ignored) {}
                                }
                                return;

                            case "NOOP":
                                logger.debug("[{}] Отправлен: 200 NOOP", clientIp);
                                writer.println("200 NOOP");
                                break;

                            case "SYST":
                                logger.debug("[{}] Отправлен: 215 UNIX Type: L8", clientIp);
                                writer.println("215 UNIX Type: L8");
                                break;

                            case "CWD":
                                logger.debug("[{}] Отправлен: 250 OK (CWD)", clientIp);
                                writer.println("250 OK");
                                break;

                            case "PWD":
                                logger.debug("[{}] Отправлен: 257 /", clientIp);
                                writer.println("257 \"/\"");
                                break;

                            case "OPTS":
                                logger.debug("[{}] Отправлен: 200 OK (OPTS)", clientIp);
                                writer.println("200 OK");
                                break;

                            case "FEAT":
                                logger.debug("[{}] Отправлен: 211 No features", clientIp);
                                writer.println("211-Features:");
                                writer.println("211 End");
                                break;

                            case "REST":
                                logger.debug("[{}] Отправлен: 350 Ready to restart", clientIp);
                                writer.println("350 Ready to restart");
                                break;

                            case "SIZE":
                                logger.debug("[{}] Отправлен: 550 Not available (SIZE)", clientIp);
                                writer.println("550 Not available");
                                break;

                            case "MDTM":
                                logger.debug("[{}] Отправлен: 550 Not available (MDTM)", clientIp);
                                writer.println("550 Not available");
                                break;

                            case "DELE":
                                logger.debug("[{}] Отправлен: 550 Not allowed (DELE)", clientIp);
                                writer.println("550 Not allowed");
                                break;

                            case "LIST":
                                logger.debug("[{}] Отправлен: 550 Not available (LIST)", clientIp);
                                writer.println("550 Not available");
                                break;

                            case "NLST":
                                logger.debug("[{}] Отправлен: 550 Not available (NLST)", clientIp);
                                writer.println("550 Not available");
                                break;

                            default:
                                logger.debug("[{}] Отправлен: 502 Command not implemented: {}", clientIp, cmd);
                                writer.println("502 Command not implemented: " + cmd);
                                logger.debug("[{}] Неизвестная команда: {}", clientIp, cmd);
                        }
                    }
                } finally {
                    // ✅ Гарантированное закрытие dataServerSocket
                    if (dataServerSocket != null && !dataServerSocket.isClosed()) {
                        try { dataServerSocket.close(); } catch (IOException ignored) {}
                    }
                }

            } catch (IOException e) {
                logger.debug("[{}] Ошибка обработки клиента: {}", clientIp, e.getMessage(), e);
            }
        } finally {
            activeConnections.decrementAndGet();
        }
    }

    /**
     * Приём файла через data-соединение (PASV).
     */
    private void handleStoreFile(PrintWriter writer, ServerSocket dataServerSocket,
                                 String fileName, String clientIp) {
        logger.debug("[{}] STOR: имя файла={}", clientIp, fileName);

        // ✅ Защита от path traversal
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            writer.println("553 Invalid file name");
            logger.warn("Path traversal попытка: {} от {}", fileName, clientIp);
            return;
        }
        //if (!fileName.equals("request.xml.sig") && !fileName.equals("request.xml")) {
        if (!allowedFileName1.equals(fileName) && !allowedFileName2.equals(fileName)) {
            logger.debug("[{}] Отправлен: 553 File name not allowed (разрешён: {} {})", clientIp, allowedFileName1, allowedFileName2);
            writer.println("553 File name not allowed. Only " + allowedFileName1 + "or" + allowedFileName2 + " is accepted");
            logger.warn("Отклонён файл: {} (разрешён только {} {})", fileName, allowedFileName1, allowedFileName2);
            return;
        }

        if (dataServerSocket == null || dataServerSocket.isClosed()) {
            logger.debug("[{}] Отправлен: 425 Use PASV first", clientIp);
            writer.println("425 Use PASV first");
            logger.warn("STOR без PASV от {}", clientIp);
            return;
        }

        logger.debug("[{}] Отправлен: 150 Ok to send data", clientIp);
        writer.println("150 Ok to send data");

        try (Socket dataSocket = dataServerSocket.accept()) {
            dataSocket.setSoTimeout(DATA_TIMEOUT);
            logger.debug("[{}] Data-соединение установлено: remote={}", clientIp, dataSocket.getRemoteSocketAddress());

            // ✅ Исправлено: toAbsolutePath() ДО normalize()
            Path outputPath = saveDirectory.resolve(fileName).toAbsolutePath().normalize();
            Path saveDirAbsolute = saveDirectory.toAbsolutePath().normalize();

            // ✅ Проверка что файл в нужной директории
            if (!outputPath.startsWith(saveDirAbsolute)) {
                logger.warn("Попытка записи вне директории: {} (saveDir: {})", outputPath, saveDirAbsolute);
                writer.println("550 Access denied");
                return;
            }

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
                        logger.debug("[{}] Отправлен: 550 File too large ({} байт)", clientIp, totalBytes);
                        writer.println("550 File too large");
                        logger.warn("Превышен лимит размера файла ({} байт) от {}", MAX_FILE_SIZE, clientIp);
                        return;
                    }
                }
            }

            logger.debug("[{}] Отправлен: 226 Transfer complete ({} байт)", clientIp, totalBytes);
            writer.println("226 Transfer complete. Received " + totalBytes + " bytes");
            logger.info("Файл сохранён: {} ({} байт) от {}", outputPath, totalBytes, clientIp);

        } catch (IOException e) {
            logger.debug("[{}] Отправлен: 426 Transfer failed: {}", clientIp, e.getMessage());
            writer.println("426 Transfer failed: " + e.getMessage());
            logger.error("Ошибка передачи файла от {}: {}", clientIp, e.getMessage(), e);
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