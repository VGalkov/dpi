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
        int len = packet.getLength();

        if (len == 0 || len > 4096) {
            logger.warn("UDP [{}]: Странный пакет, длина {}", clientIp, len);
            return;
        }

        byte[] queryData = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + len);
        Message message;

        try {
            // Пытаемся распарсить как DNS
            message = new Message(queryData);
        } catch (WireParseException e) {
            // Игнорируем не-DNS трафик (DoH/DoT handshake и т.д.)
            logger.debug("UDP [{}]: Игнорируем не-DNS трафик (длина: {}). Возможно DoH/DoT.", clientIp, len);
            return;
        } catch (Exception e) {
            logger.warn("UDP [{}]: Ошибка парсинга пакета: {}", clientIp, e.getMessage());
            return;
        }

        String domain = "unknown";
        if (message.getQuestion() != null) {
            domain = message.getQuestion().getName().toString();
        }

        logger.info("UDP [{}] -> DNS Запрос: {}", clientIp, domain);

        loadBlacklist();

        // 1. Проверка ЗАПРОСА
        if (isBlocked(domain, clientIp)) {
            logger.info("UDP [{}] <- ЗАБЛОКИРОВАНО (домен в черном списке)", clientIp);

            // ОТПРАВКА ОШИБКИ С ОБРАБОТКОЙ ИСКЛЮЧЕНИЯ
            try {
                sendRefusedResponse(socket, packet, queryData);
            } catch (IOException ioe) {
                // Критично: ошибка отправки не должна ронять весь поток workerPool
                logger.error("UDP [{}]: Не удалось отправить REFUSED ответ для домена {}. Причина: {}",
                        clientIp, domain, ioe.getMessage(), ioe);
            }
            return;
        }

        // 2. Форвардинг
        Message response = forwardToResolver(message, clientIp);

        if (response != null) {
            // 3. Проверка ОТВЕТА (IP адреса)
            if (checkResponseBlacklist(response, domain)) {
                logger.info("UDP [{}] <- ЗАБЛОКИРОВАНО (ответ содержит запрещенный IP/Домен)", clientIp);
                return; // Не отправляем ответ клиенту
            }

            // ОТПРАВКА ОТВЕТА С ОБРАБОТКОЙ ИСКЛЮЧЕНИЯ
            try {
                DatagramPacket replyPacket = getFormatedReply(response, packet);
                socket.send(replyPacket);
                logger.debug("UDP [{}] <- Ответ успешно отправлен для домена {}", clientIp, domain);
            } catch (IOException ioe) {
                logger.error("UDP [{}]: Не удалось отправить успешный ответ для домена {}. Возможно, клиент разорвал соединение или фаервол блокирует UDP. Причина: {}",
                        clientIp, domain, ioe.getMessage(), ioe);
            }
        } else {
            logger.warn("UDP [{}] <- Upstream не ответил для домена {}", clientIp, domain);

            // ОТПРАВКА ОШИБКИ UPSTREAM С ОБРАБОТКОЙ ИСКЛЮЧЕНИЯ
            try {
                sendRefusedResponse(socket, packet, queryData);
            } catch (IOException ioe) {
                logger.error("UDP [{}]: Не удалось отправить REFUSED из-за отсутствия upstream для домена {}. Причина: {}",
                        clientIp, domain, ioe.getMessage(), ioe);
            }
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
                int len;
                try {
                    len = din.readUnsignedShort();
                } catch (EOFException e) {
                    break; // Клиент закрыл соединение
                }

                byte[] requestData = new byte[len];
                din.readFully(requestData);

                Message message;
                try {
                    message = new Message(requestData);
                } catch (WireParseException e) {
                    // ЭТО ГЛАВНОЕ ИЗМЕНЕНИЕ ДЛЯ TCP:
                    // Получен не DNS over TCP трафик (например, TLS ClientHello).
                    // Просто закрываем сессию. Не пытаемся отвечать DNS-ошибкой.
                    logger.debug("TCP [{}]: Получен не-DNS трафик. Завершаем сессию.", clientIp);
                    return;
                } catch (Exception e) {
                    logger.warn("TCP [{}]: Ошибка чтения сообщения", clientIp, e.getMessage());
                    continue;
                }

                String domain = "unknown";
                if (message.getQuestion() != null) {
                    domain = message.getQuestion().getName().toString();
                }

                logger.info("TCP [{}] -> DNS Запрос: {}", clientIp, domain);

                loadBlacklist();
                if (isBlocked(domain, clientIp)) {
                    logger.info("TCP [{}] <- ЗАБЛОКИРОВАНО", clientIp);
                    Message refusedMsg = new Message(message.getHeader().getID());
                    refusedMsg.getHeader().setFlag(Flags.QR);
                    refusedMsg.getHeader().setRcode(Rcode.REFUSED);
                    byte[] errBytes = refusedMsg.toWire();
                    out.write(shortToBytes(errBytes.length));
                    out.write(errBytes);
                    out.flush();
                    continue;
                }

                Message response = forwardToResolver(message, clientIp);

                if (response != null) {
                    if (checkResponseBlacklist(response, domain)) {
                        logger.info("TCP [{}] <- ЗАБЛОКИРОВАНО (запрещенный IP в ответе)", clientIp);
                        continue; // Не отправляем ответ
                    }

                    byte[] respBytes = response.toWire();
                    out.write(shortToBytes(respBytes.length));
                    out.write(respBytes);
                    out.flush();
                } else {
                    // Логика отказа upstream...
                }
            }
        } catch (IOException e) {
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

    private DatagramPacket getFormatedReply(Message response, DatagramPacket packet) {
        byte[] respData = response.toWire();
        return new DatagramPacket(respData, respData.length, packet.getAddress(), packet.getPort());
    }

    private static byte[] shortToBytes(int value) {
        if (value < 0 || value > 0xFFFF) throw new IllegalArgumentException("Длина вне диапазона");
        return new byte[]{(byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
    }
}