package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.galkov.util.LocaleUtil;

import java.io.*;
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
 * Минималистичный FTP-сервер только для приёма request.xml.sig
 * Принимает ТОЛЬКО файл request.xml.sig, сохраняет рядом с JAR.
 *
 * @author s0506777@yandex.ru Galkov V.A.
 */
public final class RknSignatureFtpServer {
    private static final Logger logger = LoggerFactory.getLogger(RknSignatureFtpServer.class);

    // Настройки
    private final int port;
    private final Path saveDirectory;
    private final String allowedFileName;
    private final String username;
    private final String password;
    private final AtomicBoolean running = new AtomicBoolean(false);

    // Потоки
    private ServerSocket serverSocket;
    private Thread serverThread;

    public RknSignatureFtpServer() {
        // Чтение конфигурации
        String portStr = getConfig().get("blacklist.rkn.remote.ftp.port");
        this.port = parsePositiveInt(portStr, 2121);

        String saveDirStr = getConfig().get("blacklist.rkn.remote.ftp.save-dir");
        this.saveDirectory = Paths.get(saveDirStr);

        this.allowedFileName = getConfig().get("blacklist.rkn.remote.ftp.allowed-file");
        this.username = getConfig().get("blacklist.rkn.remote.ftp.username");
        this.password = getConfig().get("blacklist.rkn.remote.ftp.password");

        // Создание директории
        try {
            Files.createDirectories(saveDirectory);
        } catch (IOException e) {
            throw new RuntimeException("Не удалось создать директорию: " + saveDirectory, e);
        }

        logger.info("RknSignatureFtpServer configured: port={}, saveDir={}, allowedFile={}",
                port, saveDirectory.toAbsolutePath(), allowedFileName);
    }

    /**
     * Запуск сервера
     */
    public void start() {
        if (!running.compareAndSet(false, true)) {
            logger.warn(LocaleUtil.getString("rkn_ftp_server_already_running"));
            return;
        }

        serverThread = new Thread(this::run, "RKN-FTP-Server-Thread");
        serverThread.setDaemon(true);
        serverThread.start();

        logger.info(LocaleUtil.getString("rkn_ftp_server_started"), port);
    }

    /**
     * Остановка сервера
     */
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

        logger.info(LocaleUtil.getString("rkn_ftp_server_stopped"));
    }

    private void run() {
        try (ServerSocket localServerSocket = new ServerSocket(port)) {
            serverSocket = localServerSocket;
            logger.info(LocaleUtil.getString("rkn_ftp_server_listening"), port, saveDirectory.toAbsolutePath());

            while (running.get()) {
                try {
                    Socket clientSocket = localServerSocket.accept();
                    logger.debug("Новое подключение: {}", clientSocket.getRemoteSocketAddress());

                    // Обработка в отдельном потоке
                    new Thread(() -> handleClient(clientSocket), "RKN-FTP-Client-" + clientSocket.getPort()).start();

                } catch (IOException e) {
                    if (running.get()) {
                        logger.debug("Ошибка accept: {}", e.getMessage());
                    }
                }
            }

        } catch (IOException e) {
            if (running.get()) {
                logger.error(LocaleUtil.getString("rkn_ftp_server_critical_error"), e.getMessage(), e);
            }
        } finally {
            running.set(false);
        }
    }

    /**
     * Обработка клиента (упрощённый FTP-протокол)
     */
    private void handleClient(Socket clientSocket) {
        try (
                Socket socket = clientSocket;
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)
        ) {
            String clientIp = socket.getInetAddress().getHostAddress();
            logger.info("Подключение от: {}", clientIp);

            // 220 Welcome
            writer.println("220 RKN Signature FTP Server Ready");

            String username = null;
            boolean authenticated = false;

            while (running.get()) {
                String command = reader.readLine();
                if (command == null) break;

                logger.trace("CMD from {}: {}", clientIp, command);

                String[] parts = command.split(" ", 2);
                String cmd = parts[0].toUpperCase();

                switch (cmd) {
                    case "USER":
                        username = parts.length > 1 ? parts[1].trim() : "";
                        writer.println("331 Password required for " + username);
                        break;

                    case "PASS":
                        String password = parts.length > 1 ? parts[1].trim() : "";
                        if (this.username.equals(username) && this.password.equals(password)) {
                            authenticated = true;
                            writer.println("230 Login successful");
                            logger.info("Успешная аутентификация: {}@{}", username, clientIp);
                        } else {
                            writer.println("530 Login incorrect");
                            logger.warn("Неудачная аутентификация: {}@{}", username, clientIp);
                        }
                        break;

                    case "TYPE":
                        writer.println("200 Type set to I");
                        break;

                    case "PASV":
                        // Пассивный режим не поддерживается (только активный)
                        writer.println("200 PORT mode only");
                        break;

                    case "PORT":
                        writer.println("200 PORT command OK");
                        break;

                    case "STOR":
                        if (!authenticated) {
                            writer.println("530 Not authenticated");
                            break;
                        }
                        String fileName = parts.length > 1 ? parts[1].trim() : "";
                        handleStoreFile(writer, socket, fileName, clientIp);
                        break;

                    case "QUIT":
                        writer.println("221 Goodbye");
                        return;

                    case "NOOP":
                        writer.println("200 NOOK");
                        break;

                    case "SYST":
                        writer.println("215 UNIX Type: L8");
                        break;

                    default:
                        writer.println("502 Command not implemented");
                }
            }

        } catch (IOException e) {
            logger.debug("Ошибка обработки клиента: {}", e.getMessage());
        }
    }

    /**
     * Обработка команды STOR (загрузка файла)
     */
    private void handleStoreFile(PrintWriter writer, Socket socket,
                                 String fileName, String clientIp) throws IOException {
        logger.info("Загрузка файла: {} от {}", fileName, clientIp);

        // Проверка имени файла
        if (!allowedFileName.equals(fileName)) {
            writer.println("553 File name not allowed. Only " + allowedFileName + " is accepted");
            logger.warn("Отклонён файл: {} (разрешён только {})", fileName, allowedFileName);
            return;
        }

        writer.println("150 Ok to send data");

        // Чтение данных
        Path outputPath = saveDirectory.resolve(fileName);
        long totalBytes = 0;

        try (OutputStream fos = Files.newOutputStream(outputPath,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {

            // Чтение до EOF или лимита
            int b;
            while ((b = socket.getInputStream().read()) != -1) {
                fos.write(b);
                totalBytes++;

                // Лимит 10 МБ
                if (totalBytes > 10 * 1024 * 1024) {
                    logger.warn("Превышен лимит размера файла (10 МБ)");
                    break;
                }
            }
        }

        writer.println("226 Transfer complete. Received " + totalBytes + " bytes");
        logger.info("Файл сохранён: {} ({} байт)", outputPath.toAbsolutePath(), totalBytes);
    }

    /**
     * Парсинг положительного int
     */
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