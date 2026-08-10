package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import static ru.galkov.Main.getConfig;

public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);
    private final ExecutorService workerPool = Executors.newFixedThreadPool(getConfig().getInt("dns.thread.num"));

    private static Set<String> blacklistDomains = null;
    private static Set<String> blacklistIps = null;
    private static boolean blacklistLoaded = false;

    private synchronized void loadBlacklist() {
        if (blacklistLoaded) return;

        blacklistDomains = new HashSet<>();
        blacklistIps = new HashSet<>();

        InputStream inputStream = null;
        boolean found = false;

        URL resource = getClass().getClassLoader().getResource("blacklist.txt");

        if (resource != null) {
            try {
                inputStream = resource.openStream();
                found = true;
                logger.info("Blacklist найден в Classpath: {}", resource.toExternalForm());
            } catch (IOException e) {
                logger.error("Ошибка открытия blacklist.txt из Classpath", e);
            }
        } else {
            File file = new File("blacklist.txt");
            if (file.exists() && file.isFile()) {
                try {
                    inputStream = new FileInputStream(file);
                    found = true;
                    logger.info("Blacklist найден в рабочей директории: {}", file.getAbsolutePath());
                } catch (FileNotFoundException e) {
                    // Игнорируем
                }
            } else {
                logger.warn("Файл blacklist.txt не найден ни в Classpath, ни в рабочей директории. Блокировка отключена.");
                blacklistLoaded = true;
                return;
            }
        }

        if (found && inputStream != null) {
            try (BufferedReader br = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                String line;
                int count = 0;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;

                    if (line.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
                        blacklistIps.add(line.toLowerCase());
                    } else {
                        blacklistDomains.add(line.toLowerCase());
                    }
                    count++;
                }
                logger.info("Blacklist успешно загружен. Всего записей: {}, Доменов: {}, IP: {}",
                        count, blacklistDomains.size(), blacklistIps.size());
                blacklistLoaded = true;
            } catch (IOException e) {
                logger.error("Критическая ошибка чтения blacklist.txt", e);
                blacklistLoaded = true; // Не пытаемся читать снова
            } finally {
                try { inputStream.close(); } catch (IOException ignore) {}
            }
        } else {
            blacklistLoaded = true;
        }
    }


    private boolean isBlocked(String domain, String clientIp) {
        if (!blacklistLoaded || (blacklistDomains.isEmpty() && blacklistIps.isEmpty())) {
            return false;
        }

        if (clientIp != null && blacklistIps.contains(clientIp.toLowerCase())) {
            logger.debug("BLOCKED [IP]: Запрос от заблокированного IP {}", clientIp);
            return true;
        }

        if (domain != null && !domain.isEmpty()) {
            String dNormalized = domain.toLowerCase();
            if (dNormalized.endsWith(".")) {
                dNormalized = dNormalized.substring(0, dNormalized.length() - 1);
            }

            if (blacklistDomains.contains(dNormalized)) {
                logger.info("BLOCKED [Domain]: Точное совпадение домена {}", domain);
                return true;
            }

            for (String blocked : blacklistDomains) {
                if (dNormalized.endsWith("." + blocked) || dNormalized.equals(blocked)) {
                    logger.info("BLOCKED [Subdomain]: Домен {} совпадает с правилом {}", domain, blocked);
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Проверяет содержимое ответа DNS на наличие запрещенных доменов или IP.
     * Возвращает true, если ответ содержит что-то запрещенное.
     */
    private boolean checkResponseBlacklist(Message response, String requestedDomain) {
        if (!blacklistLoaded || (blacklistDomains.isEmpty() && blacklistIps.isEmpty())) {
            return false;
        }

        List<Record> allRecords = new ArrayList<>();
        if (response.getSection(Section.ANSWER) != null) allRecords.addAll(response.getSection(Section.ANSWER));
        if (response.getSection(Section.AUTHORITY) != null) allRecords.addAll(response.getSection(Section.AUTHORITY));
        if (response.getSection(Section.ADDITIONAL) != null) allRecords.addAll(response.getSection(Section.ADDITIONAL));

        for (Record record : allRecords) {
            Name name = record.getName();

            if (name != null) {
                String recName = name.toString().toLowerCase();

                if (recName.endsWith(".")) {
                    recName = recName.substring(0, recName.length() - 1);
                }

                if (blacklistDomains.contains(recName)) {
                    logger.info("BLOCKED [Response]: В ответе найден запрещенный домен (точное): {}", recName);
                    return true;
                }

                for (String blocked : blacklistDomains) {
                    if (recName.endsWith("." + blocked)) {
                        logger.info("BLOCKED [Response]: В ответе найден запрещенный поддомен: {} (матч: {})", recName, blocked);
                        return true;
                    }
                }
            }

            if (record instanceof ARecord) {
                ARecord a = (ARecord) record;
                String ip = a.getAddress().getHostAddress().toLowerCase();
                if (blacklistIps.contains(ip)) {
                    logger.info("BLOCKED [Response]: В ответе найден запрещенный IP: {}", ip);
                    return true;
                }
            } else if (record instanceof AAAARecord) {
                AAAARecord aaaa = (AAAARecord) record;
                String ip = aaaa.getAddress().getHostAddress().toLowerCase();
                if (blacklistIps.contains(ip)) {
                    logger.info("BLOCKED [Response]: В ответе найден запрещенный IPv6: {}", ip);
                    return true;
                }
            }
        }
        return false;
    }

    public DnsServer() {}

    public void run() {
        int port = getConfig().getShort("dns.local.port");
        logger.info("Запуск DNS форвардера на порту {}", port);

        try (
                DatagramSocket udpSocket = new DatagramSocket(port);
                ServerSocket tcpListener = new ServerSocket(port)
        ) {
            Thread tcpThread = new Thread(() -> handleTcpConnections(tcpListener));
            tcpThread.setDaemon(true);
            tcpThread.start();

            while (!Thread.currentThread().isInterrupted()) {
                DatagramPacket request = new DatagramPacket(new byte[4096], 4096);
                udpSocket.receive(request);

                String clientIp = request.getAddress().getHostAddress();
                logger.debug("UDP: Получен пакет от {}", clientIp);
                workerPool.execute(() -> processUdpRequest(udpSocket, request));
            }
        } catch (IOException e) {
            logger.error("Критическая ошибка запуска сервера", e);
        }
    }

    private void processUdpRequest(DatagramSocket socket, DatagramPacket packet) {
        String clientIp = packet.getAddress().getHostAddress();

        try {
            int len = packet.getLength();
            if (len == 0 || len > 4096) {
                logger.warn("UDP [{}]: Странный пакет, длина {}", clientIp, len);
                return;
            }

            byte[] queryData = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + len);
            Message message;

            try {
                message = new Message(queryData);
            } catch (WireParseException e) {
                logger.warn("UDP [{}]: Битый пакет", clientIp, e);
                sendRefusedResponse(socket, packet, queryData);
                return;
            } catch (Exception e) {
                logger.warn("UDP [{}]: Неизвестный формат", clientIp, e.getMessage());
                return;
            }

            String domain = "unknown";
            if (message.getQuestion() != null) {
                domain = message.getQuestion().getName().toString();
            }

            logger.info("UDP [{}] -> Запрос: {}", clientIp, domain);

            // 1. Проверка ЗАПРОСА
            loadBlacklist();
            if (isBlocked(domain, clientIp)) {
                logger.info("UDP [{}] <- ЗАБЛОКИРОВАНО (запрос). Домен: {}", clientIp, domain);
                return; // Молча отбрасываем
            }

            // 2. Форвардинг
            Message response = forwardToResolver(message, clientIp);

            if (response != null) {
                // 3. Проверка ОТВЕТА
                if (checkResponseBlacklist(response, domain)) {
                    logger.info("UDP [{}] <- ЗАБЛОКИРОВАНО (ответ содержит запрещенные данные). Домен: {}", clientIp, domain);
                    // Молча отбрасываем ответ, не отправляем клиенту
                    return;
                }

                socket.send(getFormatedReply(response, packet));
                logger.info("UDP [{}] <- Ответ отправлен", clientIp);
            } else {
                logger.warn("UDP [{}] <- Upstream не ответил", clientIp);
                sendRefusedResponse(socket, packet, queryData);
            }

        } catch (Exception e) {
            logger.error("UDP [{}]: Ошибка обработки", clientIp, e);
        }
    }

    private void sendRefusedResponse(DatagramSocket socket, DatagramPacket originalPacket, byte[] originalData) throws IOException {
        Message query = new Message(originalData);
        int id = query.getHeader() != null ? query.getHeader().getID() : 0;

        Message response = new Message(id);
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setRcode(Rcode.REFUSED);

        byte[] respBytes = response.toWire();
        DatagramPacket reply = new DatagramPacket(respBytes, respBytes.length, originalPacket.getAddress(), originalPacket.getPort());
        socket.send(reply);
    }

    private void handleTcpConnections(ServerSocket serverSocket) {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                Socket socket = serverSocket.accept();
                String clientIp = socket.getInetAddress().getHostAddress();
                logger.info("TCP: Принято соединение от {}", clientIp);
                workerPool.execute(() -> handleSingleTcpSession(socket));
            } catch (IOException e) {
                if (!Thread.currentThread().isInterrupted()) logger.debug("TCP accept error", e);
            }
        }
    }

    private void handleSingleTcpSession(Socket socket) {
        String clientIp = socket.getInetAddress().getHostAddress();
        try (Socket s = socket; InputStream in = s.getInputStream(); OutputStream out = s.getOutputStream()) {
            DataInputStream din = new DataInputStream(in);
            while (!s.isClosed()) {
                int len = din.readUnsignedShort();
                byte[] requestData = new byte[len];
                din.readFully(requestData);

                Message message = new Message(requestData);
                String domain = "unknown";
                if (message.getQuestion() != null) {
                    domain = message.getQuestion().getName().toString();
                }

                logger.info("TCP [{}] -> Запрос: {}", clientIp, domain);

                // 1. Проверка ЗАПРОСА
                loadBlacklist();
                if (isBlocked(domain, clientIp)) {
                    logger.info("TCP [{}] <- ЗАБЛОКИРОВАНО (запрос)", clientIp);
                    continue; // Пропускаем этот запрос, сессия не рвется
                }

                // 2. Форвардинг
                Message response = forwardToResolver(message, clientIp);

                if (response != null) {
                    // 3. Проверка ОТВЕТА
                    if (checkResponseBlacklist(response, domain)) {
                        logger.info("TCP [{}] <- ЗАБЛОКИРОВАНО (ответ содержит запрещенные данные)", clientIp);
                        // Молча пропускаем, не отправляем данные клиенту
                        continue;
                    }

                    byte[] respBytes = response.toWire();
                    out.write(shortToBytes(respBytes.length));
                    out.write(respBytes);
                    out.flush();
                    logger.info("TCP [{}] <- Ответ отправлен", clientIp);
                } else {
                    logger.warn("TCP [{}] <- Upstream не ответил", clientIp);
                    Message refusedMsg = new Message(message.getHeader().getID());
                    refusedMsg.getHeader().setFlag(Flags.QR);
                    refusedMsg.getHeader().setRcode(Rcode.REFUSED);

                    byte[] errBytes = refusedMsg.toWire();
                    out.write(shortToBytes(errBytes.length));
                    out.write(errBytes);
                    out.flush();
                }
            }
        } catch (Exception e) {
            if (!(e instanceof java.nio.channels.ClosedChannelException)) {
                logger.debug("TCP [{}]: Ошибка сессии", clientIp, e);
            }
        } finally {
            logger.info("TCP: Сессия с {} завершена", clientIp);
        }
    }

    private Message forwardToResolver(Message query, String clientIp) {
        String[] upstreams = getConfig().getSet("dns.list").toArray(new String[0]);
        int timeout = getConfig().getInt("dns.timeout");

        for (String dns : upstreams) {
            try {
                SimpleResolver resolver = new SimpleResolver(dns);
                resolver.setTimeout(Duration.ofSeconds(timeout));
                Message response = resolver.send(query);

                if (response != null) {
                    String domain = query.getQuestion() != null ? query.getQuestion().getName().toString() : "unknown";
                    logger.info("Запрос [{}] от [{}] выполнен через {}", domain, clientIp, dns);
                    return response;
                }
            } catch (Exception e) {
                logger.trace("Ошибка upstream {}: {}", dns, e.getMessage());
            }
        }
        return null;
    }

    private Message forwardToResolver(Message query) {
        return forwardToResolver(query, "unknown");
    }

    private DatagramPacket getFormatedReply(Message response, DatagramPacket packet) {
        byte[] respData = response.toWire();
        return new DatagramPacket(respData, respData.length, packet.getAddress(), packet.getPort());
    }

    private static byte[] shortToBytes(int value) {
        if (value < 0 || value > 0xFFFF) throw new IllegalArgumentException("Длина вне диапазона");
        return new byte[]{(byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
    }
}