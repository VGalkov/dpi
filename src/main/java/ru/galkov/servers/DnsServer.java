package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import ru.galkov.util.BlacklistLoader;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static ru.galkov.Main.getConfig;

/**
 * s0506777@yandex.ru Galkov V.A.
 *
 * DNS forwarder с проверкой blacklist:
 * - имени в вопросе;
 * - IPv4/IPv6 PTR-запросов;
 * - owner name DNS-записей;
 * - target name у CNAME/DNAME/PTR/NS/MX/SRV;
 * - IPv4 в A-record;
 * - IPv6 в AAAA-record.
 */
public class DnsServer {

    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);
    private static final String IPV4_PTR_SUFFIX = ".in-addr.arpa.";
    private static final String IPV6_PTR_SUFFIX = ".ip6.arpa.";

    private final ExecutorService workerPool =
            new ThreadPoolExecutor(
                    getConfig().getInt("dns.thread.num"),
                    getConfig().getInt("dns.thread.num"),
                    0L,
                    TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<Runnable>(500),
                    new ThreadPoolExecutor.CallerRunsPolicy()
            );

    private final BlacklistLoader blacklist;
    private final Map<String, SimpleResolver> resolvers;

    public DnsServer(BlacklistLoader blacklist) {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.resolvers = createResolvers();
    }

    private Map<String, SimpleResolver> createResolvers() {
        Map<String, SimpleResolver> result =
                new LinkedHashMap<String, SimpleResolver>();

        int timeout = getConfig().getInt("dns.timeout");

        List<String> dnsServers = getConfig().getList("dns.list");

        for (String dns : dnsServers) {
            try {
                SimpleResolver resolver = new SimpleResolver(dns);
                resolver.setTimeout(Duration.ofSeconds(timeout));
                result.put(dns, resolver);
                logger.info("DNS upstream инициализирован: {}", dns);

            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Некорректный DNS upstream: " + dns, e);
            }
        }

        if (result.isEmpty()) {
            throw new IllegalStateException("Список DNS upstream пуст");
        }

        return Collections.unmodifiableMap(result);
    }

    public void run() {
        int port = getConfig().getInt("dns.local.port");

        logger.info("Запуск DNS форвардера на порту {}", Optional.of(port));

        try (
                DatagramSocket udpSocket = new DatagramSocket(port);
                ServerSocket tcpListener = new ServerSocket(port)
        ) {
            Thread tcpThread =
                    new Thread(() -> handleTcpConnections(tcpListener), "DnsServer-TCP-Acceptor");

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
            logger.error("Критическая ошибка запуска DNS-сервера", e);
        }
    }

    private void processUdpRequest(DatagramSocket socket, DatagramPacket packet) {

        String clientIp = packet.getAddress().getHostAddress();
        int length = packet.getLength();

        if (length == 0 || length > 4096) {
            logger.warn("UDP [{}]: странный пакет, длина {}", clientIp, length);
            return;
        }

        byte[] queryData = new byte[length];

        System.arraycopy(
                packet.getData(),
                packet.getOffset(),
                queryData,
                0,
                length
        );

        Message query;

        try {
            query = new Message(queryData);
        } catch (WireParseException e) {
            logger.debug("UDP [{}]: некорректный DNS-пакет, длина {}", clientIp, length);
            return;

        } catch (Exception e) {
            logger.warn("UDP [{}]: ошибка парсинга DNS-пакета: {}", clientIp, e.getMessage());
            return;
        }

        String questionName = getQuestionName(query);
        logger.info("UDP [{}] -> DNS-запрос: {}", clientIp, questionName);

        String blockReason = checkQueryBlacklist(query);

        if (blockReason != null) {
            logger.info("UDP [{}] <- ЗАБЛОКИРОВАНО: {}; причина: {}", clientIp, questionName, blockReason);

            try {
                sendRefusedResponse(socket, packet, query);
            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED", clientIp, e);
            }

            return;
        }

        Message response = forwardToResolver(query, clientIp);

        if (response == null) {
            logger.warn("UDP [{}] <- upstream не ответил для домена {}", clientIp, questionName);

            try {
                sendRefusedResponse(socket, packet, query);

            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED " + "из-за отсутствия upstream", clientIp, e);
            }
            return;
        }

        blockReason = checkResponseBlacklist(response, questionName);

        if (blockReason != null) {
            logger.info(
                    "UDP [{}] <- ответ заблокирован: {}; причина: {}",
                    clientIp,
                    questionName,
                    blockReason
            );

            try {
                sendRefusedResponse(socket, packet, query);
            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED для заблокированного ответа", clientIp, e);
            }

            return;
        }

        try {
            DatagramPacket reply = getFormattedReply(response, packet);
            socket.send(reply);
            logger.debug("UDP [{}] <- ответ отправлен для домена {}", clientIp, questionName);

        } catch (IOException e) {
            logger.error("UDP [{}]: не удалось отправить ответ для домена {}", clientIp, questionName, e);
        }
    }

    private void handleTcpConnections(ServerSocket serverSocket) {

        while (!Thread.currentThread().isInterrupted()) {
            try {
                Socket socket = serverSocket.accept();

                String clientIp = socket.getInetAddress().getHostAddress();

                logger.info("TCP: принято соединение от {}", clientIp);

                workerPool.execute(() -> handleSingleTcpSession(socket));

            } catch (IOException e) {
                if (!Thread.currentThread().isInterrupted())
                    logger.debug("TCP accept error", e);
            }
        }
    }

    private void handleSingleTcpSession(Socket socket) {

        String clientIp = socket.getInetAddress().getHostAddress();

        try (
                Socket currentSocket = socket;
                InputStream input = currentSocket.getInputStream();
                OutputStream output = currentSocket.getOutputStream()
        ) {
            DataInputStream dataInput = new DataInputStream(input);

            while (!currentSocket.isClosed()) {
                int length;

                try {
                    length = dataInput.readUnsignedShort();

                } catch (EOFException e) {
                    break;
                }

                if (length == 0) {
                    logger.warn("TCP [{}]: получен пакет нулевой длины", clientIp);
                    break;
                }

                byte[] requestData = new byte[length];
                dataInput.readFully(requestData);
                Message query;

                try {
                    query = new Message(requestData);

                } catch (WireParseException e) {
                    logger.debug("TCP [{}]: получен некорректный DNS-пакет", clientIp);
                    return;

                } catch (Exception e) {
                    logger.warn("TCP [{}]: ошибка чтения DNS-сообщения: {}", clientIp, e.getMessage());
                    continue;
                }

                String questionName = getQuestionName(query);

                logger.info("TCP [{}] -> DNS-запрос: {}", clientIp, questionName);

                String blockReason = checkQueryBlacklist(query);

                if (blockReason != null) {
                    logger.info(
                            "TCP [{}] <- ЗАБЛОКИРОВАНО: {}; причина: {}",
                            clientIp,
                            questionName,
                            blockReason
                    );

                    sendTcpRefusedResponse(output, query);
                    continue;
                }

                Message response = forwardToResolver(query, clientIp);

                if (response == null) {
                    logger.warn("TCP [{}] <- upstream не ответил: {}", clientIp, questionName);
                    sendTcpRefusedResponse(output, query);
                    continue;
                }

                blockReason = checkResponseBlacklist(response, questionName);

                if (blockReason != null) {
                    logger.info(
                            "TCP [{}] <- ответ заблокирован: {}; " +
                                    "причина: {}",
                            clientIp,
                            questionName,
                            blockReason
                    );

                    sendTcpRefusedResponse(output, query);
                    continue;
                }

                byte[] responseBytes = response.toWire();

                output.write(shortToBytes(responseBytes.length));
                output.write(responseBytes);
                output.flush();
            }

        } catch (IOException e) {
            if (!(e instanceof java.nio.channels.ClosedChannelException)) {
                logger.debug("TCP [{}]: ошибка сессии", clientIp, e);
            }

        } finally {
            logger.info("TCP: сессия с {} завершена", clientIp);
        }
    }

    /**
     * Проверяет DNS-вопрос до запроса к upstream.
     *
     * @return причина блокировки либо null, если запрос разрешён.
     */
    private String checkQueryBlacklist(Message query) {

        Record question = query.getQuestion();
        if (question == null) return null;

        String questionName = question.getName().toString();

        if (blacklist.isBlockedDomain(questionName))
            return "запрещённый домен в DNS-вопросе: " + questionName;

        String ipv4 = extractIpv4FromPtrQuery(questionName);

        if (ipv4 != null && blacklist.isBlockedIp(ipv4)) {
            return "запрещённый IPv4 в PTR-запросе: " + ipv4;
        }

        String ipv6 = extractIpv6FromPtrQuery(questionName);

        if (ipv6 != null && blacklist.isBlockedIp(ipv6))
            return "запрещённый IPv6 в PTR-запросе: " + ipv6;
        return null;
    }

    /**
     * Проверяет все записи ответа в ANSWER, AUTHORITY и ADDITIONAL.
     *
     * @return причина блокировки либо null, если ответ разрешён.
     */
    private String checkResponseBlacklist(Message response, String requestedDomain) {

        int[] sections = {
                Section.ANSWER,
                Section.AUTHORITY,
                Section.ADDITIONAL
        };

        for (int section : sections) {
            List<Record> records = response.getSection(section);

            if (records == null) continue;


            for (Record record : records) {
                String blockReason = checkRecordBlacklist(record, section, requestedDomain);
                if (blockReason != null)
                    return blockReason;
            }
        }

        return null;
    }

    /**
     * Проверяет одну DNS-запись:
     * owner name, IP-адреса и доменные target-поля.
     */
    private String checkRecordBlacklist(Record record, int section, String requestedDomain) {

        if (record == null) return null;
        Name ownerName = record.getName();

        if (ownerName != null && blacklist.isBlockedDomain(ownerName.toString())) {
            return "запрещённый owner domain " +
                    ownerName +
                    " в секции " +
                    Section.string(section) +
                    " для запроса " +
                    requestedDomain;
        }

        if (record instanceof ARecord) {
            String ip = ((ARecord) record).getAddress().getHostAddress();
            if (blacklist.isBlockedIp(ip)) {
                return "запрещённый IPv4 " +
                        ip +
                        " в A-record, секция " +
                        Section.string(section);
            }

            return null;
        }

        if (record instanceof AAAARecord) {
            String ip = ((AAAARecord) record).getAddress().getHostAddress();
            if (blacklist.isBlockedIp(ip))
                return "запрещённый IPv6 " + ip + " в AAAA-record, секция " + Section.string(section);

            return null;
        }

        Name targetName = extractTargetName(record);

        if (targetName != null && blacklist.isBlockedDomain(targetName.toString())) {
            return "запрещённый target domain " +
                    targetName +
                    " в " +
                    record.getClass()
                            .getSimpleName() +
                    ", секция " +
                    Section.string(section);
        }

        return null;
    }

    /**
     * Извлекает target-имя из DNS-записей, содержащих другое доменное имя.
     */
    private Name extractTargetName(Record record) {

        if (record instanceof CNAMERecord)
            return ((CNAMERecord) record).getTarget();

        if (record instanceof DNAMERecord)
            return ((DNAMERecord) record).getTarget();

        if (record instanceof PTRRecord)
            return ((PTRRecord) record).getTarget();

        if (record instanceof NSRecord)
            return ((NSRecord) record).getTarget();

        if (record instanceof MXRecord)
            return ((MXRecord) record).getTarget();


        if (record instanceof SRVRecord)
            return ((SRVRecord) record).getTarget();

        return null;
    }

    private Message forwardToResolver(Message query, String clientIp) {

        String domain = getQuestionName(query);

        for (Map.Entry<String, SimpleResolver> entry : resolvers.entrySet()) {

            String dns = entry.getKey();

            SimpleResolver resolver = entry.getValue();

            try {
                Message response = resolver.send(query);

                if (response != null) {
                    logger.info(
                            "Запрос [{}] от [{}] выполнен через {}",
                            domain,
                            clientIp,
                            dns
                    );
                    return response;
                }

            } catch (Exception e) {
                logger.trace("Ошибка upstream {}: {}", dns, e.getMessage());
            }
        }

        return null;
    }

    private void sendRefusedResponse(DatagramSocket socket, DatagramPacket originalPacket, Message query) throws IOException {

        Message response = createRefusedResponse(query);

        byte[] responseBytes = response.toWire();

        DatagramPacket reply =
                new DatagramPacket(
                        responseBytes,
                        responseBytes.length,
                        originalPacket.getAddress(),
                        originalPacket.getPort()
                );

        socket.send(reply);
    }

    private void sendTcpRefusedResponse(OutputStream output, Message query) throws IOException {

        Message refused = createRefusedResponse(query);
        byte[] refusedBytes = refused.toWire();
        output.write(shortToBytes(refusedBytes.length));
        output.write(refusedBytes);
        output.flush();
    }

    private Message createRefusedResponse(Message query) {

        Message response = (Message) query.clone();
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setRcode(Rcode.REFUSED);
        return response;
    }

    private DatagramPacket getFormattedReply(Message response, DatagramPacket requestPacket) {

        byte[] responseData = response.toWire();

        return new DatagramPacket(
                responseData,
                responseData.length,
                requestPacket.getAddress(),
                requestPacket.getPort()
        );
    }

    private String getQuestionName(Message message) {

        Record question = message.getQuestion();

        if (question == null || question.getName() == null)
            return "unknown";
        return question.getName().toString();
    }

    /**
     * Преобразует
     * 93.226.237.209.in-addr.arpa.
     * в IPv4:
     * 209.237.226.93.
     */
    private String extractIpv4FromPtrQuery(String ptrName) {

        if (ptrName == null) return null;
        String name = ptrName.toLowerCase(Locale.ROOT);
        if (!name.endsWith(IPV4_PTR_SUFFIX))
            return null;

        String reversedIp = name.substring(0, name.length() - IPV4_PTR_SUFFIX.length());
        String[] parts = reversedIp.split("\\.");

        if (parts.length != 4)
            return null;

        String ip = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
        return blacklist.isBlockedIp(ip) || isValidIpLiteral(ip) ? ip : null;
    }

    /**
     * Преобразует IPv6 reverse DNS имя:
     *
     * b.a.9.8.7.6.5.0.4.0.0.0.0.0.0.0.0.0
     * .0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.ip6.arpa.
     *
     * в нормальный IPv6 address.
     */
    private String extractIpv6FromPtrQuery(String ptrName) {

        if (ptrName == null)
            return null;

        String name = ptrName.toLowerCase(Locale.ROOT);
        if (!name.endsWith(IPV6_PTR_SUFFIX))
            return null;

        String reversedNibbles = name.substring(0, name.length() - IPV6_PTR_SUFFIX.length());
        String[] nibbles = reversedNibbles.split("\\.");

        if (nibbles.length != 32)
            return null;


        StringBuilder hexadecimal = new StringBuilder(32);

        for (int i = nibbles.length - 1; i >= 0; i--) {

            String nibble = nibbles[i];
            if (nibble.length() != 1 || Character.digit(nibble.charAt(0), 16) < 0)
                return null;

            hexadecimal.append(nibble);
        }

        StringBuilder ipv6 = new StringBuilder(39);

        for (int i = 0; i < hexadecimal.length(); i += 4) {

            if (i > 0)
                ipv6.append(':');

            ipv6.append(hexadecimal, i, i + 4);
        }

        return ipv6.toString();
    }

    private boolean isValidIpLiteral(String value) {

        if (value == null || value.isEmpty())
            return false;


        String[] parts = value.split("\\.", -1);

        if (parts.length != 4)
            return false;


        for (String part : parts) {
            if (part.isEmpty())
                return false;


            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i)))
                    return false;
            }

            try {
                int number = Integer.parseInt(part);
                if (number < 0 || number > 255)
                    return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    private static byte[] shortToBytes(int value) {

        if (value < 0 || value > 0xFFFF)
            throw new IllegalArgumentException("Длина вне диапазона: " + value);

        return new byte[]{(byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
    }
}