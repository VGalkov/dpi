package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import ru.galkov.llm.DnsAnomalyDetector;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.LogFields;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

import static ru.galkov.Main.getConfig;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public class DnsServer {

    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);
    private static final String IPV4_PTR_SUFFIX = ".in-addr.arpa.";
    private static final String IPV6_PTR_SUFFIX = ".ip6.arpa.";
    private final DnsAnomalyDetector dnsAnomalyDetector;

    private final ExecutorService workerPool = new ThreadPoolExecutor(
            getConfig().getInt("dns.thread.num"),
            getConfig().getInt("dns.thread.num"),
            0L,
            TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<Runnable>(500),
            new ThreadPoolExecutor.CallerRunsPolicy()

    );

    private final BlacklistLoader blacklist;
    private final Map<String, SimpleResolver> resolvers;
    private final DnsRateLimiter rateLimiter;

    private final Object lifecycleLock = new Object();

    private volatile boolean running;
    private volatile DatagramSocket udpSocket;
    private volatile ServerSocket tcpListener;
    private volatile Thread tcpThread;

    public DnsServer(BlacklistLoader blacklist, DnsAnomalyDetector dnsAnomalyDetector)  {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.resolvers = createResolvers();
        this.dnsAnomalyDetector = dnsAnomalyDetector;
        this.rateLimiter = createRateLimiter();
    }

    public void run() {
        synchronized (lifecycleLock) {
            if (running) {
                logger.warn("DNS server уже запущен");
                return;
            }

            running = true;
        }

        int port = getConfig().getInt("dns.local.port");

        logger.info("Запуск DNS форвардера на порту {}", Optional.of(port));

        try (
                DatagramSocket localUdpSocket = new DatagramSocket(port);
                ServerSocket localTcpListener = new ServerSocket(port)
        ) {
            udpSocket = localUdpSocket;
            tcpListener = localTcpListener;

            startTcpAcceptor(localTcpListener);

            while (running) {
                DatagramPacket request = new DatagramPacket(new byte[4096], 4096);

                try {
                    localUdpSocket.receive(request);
                } catch (SocketException e) {
                    if (!running) {
                        break;
                    }

                    throw e;
                }

                if (!running) {
                    break;
                }

                String clientIp = request.getAddress().getHostAddress();

                logger.debug("UDP: Получен пакет от {}", clientIp);

                try {
                    workerPool.execute(() -> processUdpRequest(localUdpSocket, request));
                } catch (RuntimeException e) {
                    logger.warn("DNS worker pool отклонил UDP-запрос от {}: {}", clientIp, e.getMessage());
                }
            }

        } catch (IOException e) {
            if (running) {
                logger.error("Критическая ошибка запуска DNS-сервера", e);
            } else {
                logger.info("DNS server остановлен");
            }

        } finally {
            running = false;
            udpSocket = null;
            tcpListener = null;

            shutdownWorkerPool();

            logger.info("DNS server завершил работу");
        }
    }

    public void stop() {
        synchronized (lifecycleLock) {
            if (!running) {
                return;
            }

            logger.info("Остановка DNS server начата");

            running = false;

            closeQuietly(udpSocket);
            closeQuietly(tcpListener);

            Thread currentTcpThread = tcpThread;

            if (currentTcpThread != null) {
                currentTcpThread.interrupt();
            }
        }

        shutdownWorkerPool();

        logger.info("Остановка DNS server завершена");
    }

    private void startTcpAcceptor(ServerSocket serverSocket) {
        tcpThread = new Thread(
                () -> handleTcpConnections(serverSocket),
                "DnsServer-TCP-Acceptor"
        );

        tcpThread.setDaemon(false);
        tcpThread.start();
    }

    private void handleTcpConnections(ServerSocket serverSocket) {
        while (running) {
            try {
                Socket socket = serverSocket.accept();

                if (!running) {
                    closeQuietly(socket);
                    break;
                }

                String clientIp = socket.getInetAddress().getHostAddress();

                logger.info("TCP: принято соединение от {}", clientIp);

                try {
                    workerPool.execute(() -> handleSingleTcpSession(socket));
                } catch (RuntimeException e) {
                    logger.warn("DNS worker pool отклонил TCP-соединение от {}: {}", clientIp, e.getMessage());
                    closeQuietly(socket);
                }

            } catch (SocketException e) {
                if (running) {
                    logger.warn("TCP accept error: {}", e.getMessage());
                }

                break;

            } catch (IOException e) {
                if (running) {
                    logger.debug("TCP accept error", e);
                }
            }
        }

        logger.info("DNS TCP acceptor завершён");
    }

    private void shutdownWorkerPool() {
        workerPool.shutdown();

        try {
            if (!workerPool.awaitTermination(10, TimeUnit.SECONDS)) {
                logger.warn("DNS worker pool не завершился за 10 секунд, выполняется shutdownNow");
                workerPool.shutdownNow();
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            workerPool.shutdownNow();
        }
    }

    private void closeQuietly(DatagramSocket socket) {
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
    }

    private void closeQuietly(ServerSocket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }

        try {
            socket.close();
        } catch (IOException e) {
            logger.debug("Ошибка закрытия DNS TCP listener: {}", e.getMessage());
        }
    }

    private void closeQuietly(Socket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }

        try {
            socket.close();
        } catch (IOException e) {
            logger.debug("Ошибка закрытия DNS client socket: {}", e.getMessage());
        }
    }

    private DnsRateLimiter createRateLimiter() {
        boolean enabled = getConfig().getBoolean("dns.rate-limit.enabled");

        if (!enabled) {
            logger.info("DNS rate limit отключён");
            return DnsRateLimiter.disabled();
        }

        int requestsPerSecond = getConfig().getInt("dns.rate-limit.requests-per-second");
        int burst = getConfig().getInt("dns.rate-limit.burst");
        int clientIdleSeconds = getConfig().getInt("dns.rate-limit.client-idle-seconds");

        if (requestsPerSecond <= 0) {
            throw new IllegalArgumentException("dns.rate-limit.requests-per-second должен быть больше 0");
        }

        if (burst <= 0) {
            throw new IllegalArgumentException("dns.rate-limit.burst должен быть больше 0");
        }

        if (clientIdleSeconds <= 0) {
            throw new IllegalArgumentException("dns.rate-limit.client-idle-seconds должен быть больше 0");
        }

        logger.info("DNS rate limit включён: requestsPerSecond={}, burst={}, clientIdleSeconds={}",
                requestsPerSecond, burst, clientIdleSeconds);

        return new DnsRateLimiter(requestsPerSecond, burst, TimeUnit.SECONDS.toNanos(clientIdleSeconds));
    }

    private Map<String, SimpleResolver> createResolvers() {
        Map<String, SimpleResolver> result = new LinkedHashMap<String, SimpleResolver>();
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

    private void processUdpRequest(DatagramSocket socket, DatagramPacket packet) {
        String clientIp = packet.getAddress().getHostAddress();
        int length = packet.getLength();

        if (length == 0 || length > 4096) {
            logger.warn("UDP [{}]: странный пакет, длина {}", clientIp, length);
            return;
        }

        byte[] queryData = new byte[length];

        System.arraycopy(packet.getData(), packet.getOffset(), queryData, 0, length);

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

        if (!rateLimiter.tryAcquire(clientIp)) {
            logger.warn("{} {} {} {} {} {}",
                    LogFields.kv("event", "DNS_RATE_LIMIT"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("transport", "UDP"),
                    LogFields.kv("qname", questionName),
                    LogFields.kv("requestsPerSecond", rateLimiter.getRequestsPerSecond()),
                    LogFields.kv("burst", rateLimiter.getBurst()));

            try {
                sendRefusedResponse(socket, packet, query);
            } catch (IOException e) {
                logger.debug("UDP [{}]: не удалось отправить REFUSED для rate limit", clientIp, e);
            }

            return;
        }

        logger.info("{} {} {} {}",
                LogFields.kv("event", "DNS_QUERY"),
                LogFields.kv("client", clientIp),
                LogFields.kv("transport", "UDP"),
                LogFields.kv("qname", questionName));

        String blockReason = checkQueryBlacklist(query);

        if (blockReason != null) {
            logger.info("{} {} {} {} {} {}",
                    LogFields.kv("event", "DNS_BLOCK"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("transport", "UDP"),
                    LogFields.kv("qname", questionName),
                    LogFields.kv("reason", "QUERY"),
                    LogFields.kv("detail", blockReason));

            try {
                sendRefusedResponse(socket, packet, query);
            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED", clientIp, e);
            }

            return;
        }

        if (dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled()) {
            int queryType = query.getQuestion().getType();
            boolean isQuery = !query.getHeader().getFlag(Flags.QR);
            int opcode = query.getHeader().getOpcode();
            boolean isTruncated = query.getHeader().getFlag(Flags.TC);
            boolean recursionDesired = query.getHeader().getFlag(Flags.RD);
            int rcode = query.getHeader().getRcode();

            dnsAnomalyDetector.recordQuery(clientIp, questionName, queryType,
                    isQuery, opcode, isTruncated, recursionDesired, 0, rcode);
        }

        Message response = forwardToResolver(query, clientIp);

        if (response == null) {
            logger.warn("{} {} {} {} {}",
                    LogFields.kv("event", "DNS_UPSTREAM_NO_RESPONSE"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("transport", "UDP"),
                    LogFields.kv("qname", questionName));

            try {
                sendRefusedResponse(socket, packet, query);
            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED из-за отсутствия upstream", clientIp, e);
            }

            return;
        }

        blockReason = checkResponseBlacklist(response, questionName);

        if (blockReason != null) {
            logger.info("{} {} {} {} {} {}",
                    LogFields.kv("event", "DNS_BLOCK"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("transport", "UDP"),
                    LogFields.kv("qname", questionName),
                    LogFields.kv("reason", "RESPONSE"),
                    LogFields.kv("detail", blockReason));

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
            logger.debug("{} {} {} {}",
                    LogFields.kv("event", "DNS_RESPONSE_SENT"),
                    LogFields.kv("client", clientIp),
                    LogFields.kv("transport", "UDP"),
                    LogFields.kv("qname", questionName));

        } catch (IOException e) {
            if (running) {
                logger.error("UDP [{}]: не удалось отправить ответ для домена {}", clientIp, questionName, e);
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

            while (running && !currentSocket.isClosed()) {
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

                if (!rateLimiter.tryAcquire(clientIp)) {
                    logger.warn("{} {} {} {} {} {}",
                            LogFields.kv("event", "DNS_RATE_LIMIT"),
                            LogFields.kv("client", clientIp),
                            LogFields.kv("transport", "TCP"),
                            LogFields.kv("qname", questionName),
                            LogFields.kv("requestsPerSecond", rateLimiter.getRequestsPerSecond()),
                            LogFields.kv("burst", rateLimiter.getBurst()));

                    sendTcpRefusedResponse(output, query);
                    continue;
                }

                logger.info("{} {} {} {}",
                        LogFields.kv("event", "DNS_QUERY"),
                        LogFields.kv("client", clientIp),
                        LogFields.kv("transport", "TCP"),
                        LogFields.kv("qname", questionName));

                String blockReason = checkQueryBlacklist(query);

                if (blockReason != null) {
                    logger.info("TCP [{}] <- ЗАБЛОКИРОВАНО: {}; причина: {}", clientIp, questionName, blockReason);
                    sendTcpRefusedResponse(output, query);
                    continue;
                }

                if (dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled()) {
                    int queryType = query.getQuestion().getType();
                    boolean isQuery = !query.getHeader().getFlag(Flags.QR);
                    int opcode = query.getHeader().getOpcode();
                    boolean isTruncated = query.getHeader().getFlag(Flags.TC);
                    boolean recursionDesired = query.getHeader().getFlag(Flags.RD);
                    int rcode = query.getHeader().getRcode();

                    dnsAnomalyDetector.recordQuery(clientIp, questionName, queryType,
                            isQuery, opcode, isTruncated, recursionDesired, 0, rcode);
                }

                Message response = forwardToResolver(query, clientIp);

                if (response == null) {
                    logger.warn("TCP [{}] <- upstream не ответил: {}", clientIp, questionName);
                    sendTcpRefusedResponse(output, query);
                    continue;
                }

                blockReason = checkResponseBlacklist(response, questionName);

                if (blockReason != null) {
                    logger.info("TCP [{}] <- ответ заблокирован: {}; причина: {}", clientIp, questionName, blockReason);
                    sendTcpRefusedResponse(output, query);
                    continue;
                }

                byte[] responseBytes = response.toWire();

                output.write(shortToBytes(responseBytes.length));
                output.write(responseBytes);
                output.flush();
            }

        } catch (IOException e) {
            if (running && !(e instanceof java.nio.channels.ClosedChannelException)) {
                logger.debug("TCP [{}]: ошибка сессии", clientIp, e);
            }

        } finally {
            logger.info("{} {}",
                    LogFields.kv("event", "DNS_TCP_SESSION_END"),
                    LogFields.kv("client", clientIp));
        }
    }

    private String checkQueryBlacklist(Message query) {
        Record question = query.getQuestion();

        if (question == null) {
            return null;
        }

        String questionName = question.getName().toString();

        if (blacklist.isBlockedDomain(questionName)) {
            return "запрещённый домен в DNS-вопросе: " + questionName;
        }

        String ipv4 = extractIpv4FromPtrQuery(questionName);

        if (ipv4 != null && blacklist.isBlockedIp(ipv4)) {
            return "запрещённый IPv4 в PTR-запросе: " + ipv4;
        }

        String ipv6 = extractIpv6FromPtrQuery(questionName);

        if (ipv6 != null && blacklist.isBlockedIp(ipv6)) {
            return "запрещённый IPv6 в PTR-запросе: " + ipv6;
        }

        return null;
    }

    private String checkResponseBlacklist(Message response, String requestedDomain) {
        int[] sections = {
                Section.ANSWER,
                Section.AUTHORITY,
                Section.ADDITIONAL
        };

        for (int section : sections) {
            List<Record> records = response.getSection(section);

            if (records == null) {
                continue;
            }

            for (Record record : records) {
                String blockReason = checkRecordBlacklist(record, section, requestedDomain);

                if (blockReason != null) {
                    return blockReason;
                }
            }
        }

        return null;
    }

    private String checkRecordBlacklist(Record record, int section, String requestedDomain) {
        if (record == null) {
            return null;
        }

        Name ownerName = record.getName();

        if (ownerName != null && blacklist.isBlockedDomain(ownerName.toString())) {
            return "запрещённый owner domain " + ownerName
                    + " в секции " + Section.string(section)
                    + " для запроса " + requestedDomain;
        }

        if (record instanceof ARecord) {
            String ip = ((ARecord) record).getAddress().getHostAddress();

            if (blacklist.isBlockedIp(ip)) {
                return "запрещённый IPv4 " + ip
                        + " в A-record, секция " + Section.string(section);
            }

            return null;
        }

        if (record instanceof AAAARecord) {
            String ip = ((AAAARecord) record).getAddress().getHostAddress();

            if (blacklist.isBlockedIp(ip)) {
                return "запрещённый IPv6 " + ip
                        + " в AAAA-record, секция " + Section.string(section);
            }

            return null;
        }

        Name targetName = extractTargetName(record);

        if (targetName != null && blacklist.isBlockedDomain(targetName.toString())) {
            return "запрещённый target domain " + targetName
                    + " в " + record.getClass().getSimpleName()
                    + ", секция " + Section.string(section);
        }

        return null;
    }

    private Name extractTargetName(Record record) {
        if (record instanceof CNAMERecord) {
            return ((CNAMERecord) record).getTarget();
        }

        if (record instanceof DNAMERecord) {
            return ((DNAMERecord) record).getTarget();
        }

        if (record instanceof PTRRecord) {
            return ((PTRRecord) record).getTarget();
        }

        if (record instanceof NSRecord) {
            return ((NSRecord) record).getTarget();
        }

        if (record instanceof MXRecord) {
            return ((MXRecord) record).getTarget();
        }

        if (record instanceof SRVRecord) {
            return ((SRVRecord) record).getTarget();
        }

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
                    logger.info("Запрос [{}] от [{}] выполнен через {}", domain, clientIp, dns);

                    if (response.getHeader().getFlag(Flags.TC)) {
                        logger.info("Запрос [{}] от [{}]: получен truncated ответ (TC=1), делаем TCP fallback к {}",
                                domain, clientIp, dns);

                        response = forwardToResolverTcp(query, resolver, dns);
                    }

                    return response;
                }

            } catch (Exception e) {
                logger.trace("Ошибка upstream {}: {}", dns, e.getMessage());
            }
        }

        return null;
    }
    private Message forwardToResolverTcp(Message query, SimpleResolver resolver, String dns) {
        try {
            resolver.setTCP(true);
            Message tcpResponse = resolver.send(query);
            resolver.setTCP(false);

            if (tcpResponse != null) {
                logger.info("Запрос [{}]: TCP fallback через {} успешен", getQuestionName(query), dns);
            }

            return tcpResponse;

        } catch (Exception e) {
            logger.warn("Запрос [{}]: TCP fallback через {} не удался: {}",
                    getQuestionName(query), dns, e.getMessage());

            resolver.setTCP(false);
            return null;
        }
    }
    private void sendRefusedResponse(DatagramSocket socket, DatagramPacket originalPacket, Message query) throws IOException {
        Message response = createRefusedResponse(query);
        byte[] responseBytes = response.toWire();

        DatagramPacket reply = new DatagramPacket(
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

        if (question == null || question.getName() == null) {
            return "unknown";
        }

        return question.getName().toString();
    }

    private String extractIpv4FromPtrQuery(String ptrName) {
        if (ptrName == null) {
            return null;
        }

        String name = ptrName.toLowerCase(Locale.ROOT);

        if (!name.endsWith(IPV4_PTR_SUFFIX)) {
            return null;
        }

        String reversedIp = name.substring(0, name.length() - IPV4_PTR_SUFFIX.length());
        String[] parts = reversedIp.split("\\.");

        if (parts.length != 4) {
            return null;
        }

        String ip = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];

        return isValidIpv4Literal(ip) ? ip : null;
    }

    private String extractIpv6FromPtrQuery(String ptrName) {
        if (ptrName == null) {
            return null;
        }

        String name = ptrName.toLowerCase(Locale.ROOT);

        if (!name.endsWith(IPV6_PTR_SUFFIX)) {
            return null;
        }

        String reversedNibbles = name.substring(0, name.length() - IPV6_PTR_SUFFIX.length());
        String[] nibbles = reversedNibbles.split("\\.");

        if (nibbles.length != 32) {
            return null;
        }

        StringBuilder hexadecimal = new StringBuilder(32);

        for (int i = nibbles.length - 1; i >= 0; i--) {
            String nibble = nibbles[i];

            if (nibble.length() != 1 || Character.digit(nibble.charAt(0), 16) < 0) {
                return null;
            }

            hexadecimal.append(nibble);
        }

        StringBuilder ipv6 = new StringBuilder(39);

        for (int i = 0; i < hexadecimal.length(); i += 4) {
            if (i > 0) {
                ipv6.append(':');
            }

            ipv6.append(hexadecimal, i, i + 4);
        }

        return ipv6.toString();
    }

    private boolean isValidIpv4Literal(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String[] parts = value.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }

            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }

            try {
                int number = Integer.parseInt(part);

                if (number < 0 || number > 255) {
                    return false;
                }

            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    private static byte[] shortToBytes(int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException("Длина вне диапазона: " + value);
        }

        return new byte[]{
                (byte) ((value >> 8) & 0xFF),
                (byte) (value & 0xFF)
        };
    }

    private static final class DnsRateLimiter {

        private final boolean enabled;
        private final int requestsPerSecond;
        private final int burst;
        private final long clientIdleNanos;
        private final ConcurrentHashMap<String, TokenBucket> buckets;
        private volatile long nextCleanupNanos;

        private DnsRateLimiter(boolean enabled, int requestsPerSecond, int burst,
                               long clientIdleNanos, ConcurrentHashMap<String, TokenBucket> buckets) {
            this.enabled = enabled;
            this.requestsPerSecond = requestsPerSecond;
            this.burst = burst;
            this.clientIdleNanos = clientIdleNanos;
            this.buckets = buckets;
        }

        private static DnsRateLimiter disabled() {
            return new DnsRateLimiter(false, 0, 0, 0L, new ConcurrentHashMap<String, TokenBucket>());
        }

        private DnsRateLimiter(int requestsPerSecond, int burst, long clientIdleNanos) {
            this(true, requestsPerSecond, burst, clientIdleNanos, new ConcurrentHashMap<String, TokenBucket>());
        }

        private boolean tryAcquire(String clientIp) {
            if (!enabled) {
                return true;
            }

            long now = System.nanoTime();

            cleanupIfNeeded(now);

            TokenBucket bucket = buckets.computeIfAbsent(clientIp, ignored -> new TokenBucket(burst, now));

            return bucket.tryAcquire(now, requestsPerSecond, burst);
        }

        private void cleanupIfNeeded(long now) {
            long cleanupIntervalNanos = Math.min(clientIdleNanos, TimeUnit.SECONDS.toNanos(60));

            if (now < nextCleanupNanos) {
                return;
            }

            synchronized (this) {
                if (now < nextCleanupNanos) {
                    return;
                }

                for (Map.Entry<String, TokenBucket> entry : buckets.entrySet()) {
                    TokenBucket bucket = entry.getValue();

                    if (now - bucket.getLastSeenNanos() > clientIdleNanos) {
                        buckets.remove(entry.getKey(), bucket);
                    }
                }

                nextCleanupNanos = now + cleanupIntervalNanos;
            }
        }

        private int getRequestsPerSecond() {
            return requestsPerSecond;
        }

        private int getBurst() {
            return burst;
        }
    }

    private static final class TokenBucket {

        private double tokens;
        private long lastRefillNanos;
        private long lastSeenNanos;

        private TokenBucket(int burst, long now) {
            this.tokens = burst;
            this.lastRefillNanos = now;
            this.lastSeenNanos = now;
        }

        private synchronized boolean tryAcquire(long now, int requestsPerSecond, int burst) {
            long elapsedNanos = now - lastRefillNanos;

            if (elapsedNanos > 0) {
                double newTokens = (elapsedNanos / 1_000_000_000.0d) * requestsPerSecond;

                tokens = Math.min(burst, tokens + newTokens);
                lastRefillNanos = now;
            }

            lastSeenNanos = now;

            if (tokens < 1.0d) {
                return false;
            }

            tokens -= 1.0d;
            return true;
        }

        private synchronized long getLastSeenNanos() {
            return lastSeenNanos;
        }
    }
}