package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static ru.galkov.Main.getConfig;

public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);
    private final ExecutorService workerPool =
            new ThreadPoolExecutor(
                    getConfig().getInt("dns.thread.num"),
                    getConfig().getInt("dns.thread.num"),
                    0L,
                    TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(500),
                    new ThreadPoolExecutor.CallerRunsPolicy()
            );

    private final BlacklistLoader blacklist;

    private final Map<String, SimpleResolver> resolvers;

    public DnsServer(BlacklistLoader blacklist) {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.resolvers = createResolvers();
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

    private boolean checkResponseBlacklist(Message response, String requestedDomain) {

        List<Record> records = new ArrayList<Record>();

        addRecords(records, response, Section.ANSWER);

        addRecords(records, response, Section.AUTHORITY);

        addRecords(records, response, Section.ADDITIONAL);

        for (Record record : records) {
            Name name = record.getName();

            if (name != null && blacklist.isBlockedDomain(name.toString())) {

                logger.info("BLOCKED [Response]: запрещённый домен {} для запроса {}", name, requestedDomain);
                return true;
            }

            if (record instanceof ARecord) {
                ARecord aRecord = (ARecord) record;

                String ip = aRecord.getAddress().getHostAddress().toLowerCase(Locale.ROOT);

                if (blacklist.isBlockedIp(ip)) {
                    logger.info("BLOCKED [Response]: запрещённый IPv4 {}", ip);
                    return true;
                }
            }

            if (record instanceof AAAARecord) {
                AAAARecord aaaaRecord = (AAAARecord) record;

                String ip = aaaaRecord.getAddress().getHostAddress().toLowerCase(Locale.ROOT);

                if (blacklist.isBlockedIp(ip)) {
                    logger.info("BLOCKED [Response]: запрещённый IPv6 {}", ip);

                    return true;
                }
            }
        }

        return false;
    }

    private void addRecords(List<Record> target, Message message, int section) {

        List<Record> sectionRecords = message.getSection(section);

        if (sectionRecords != null) {
            target.addAll(sectionRecords);
        }
    }

    public void run() {
        int port = getConfig().getInt("dns.local.port");

        logger.info("Запуск DNS форвардера на порту {}", Optional.of(port));

        try (
                DatagramSocket udpSocket = new DatagramSocket(port);
                ServerSocket tcpListener = new ServerSocket(port)
        ) {
            Thread tcpThread = new Thread(() -> handleTcpConnections(tcpListener), "DnsServer-TCP-Acceptor");
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
        int len = packet.getLength();

        if (len == 0 || len > 4096) {
            logger.warn("UDP [" + clientIp + "]: странный пакет, длина " + len);

            return;
        }

        byte[] queryData = new byte[len];

        System.arraycopy(packet.getData(), packet.getOffset(), queryData, 0, len);

        Message message;

        try {
            message = new Message(queryData);

        } catch (WireParseException e) {
            logger.debug("UDP [" + clientIp + "]: некорректный DNS-пакет, длина" + len);
            return;

        } catch (Exception e) {
            logger.warn("UDP [{}]: ошибка парсинга пакета: {}", clientIp, e.getMessage());
            return;
        }

        String domain = "unknown";

        if (message.getQuestion() != null) {
            domain = message.getQuestion().getName().toString();
        }

        logger.info("UDP [{}] -> DNS-запрос: {}", clientIp, domain);

        if (blacklist.isBlocked(domain, clientIp)) {
            logger.info("UDP [{}] <- ЗАБЛОКИРОВАНО: {}", clientIp, domain);

            try {
                sendRefusedResponse(socket, packet, message);

            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED", clientIp, e);
            }

            return;
        }

        Message response = forwardToResolver(message, clientIp);

        if (response == null) {
            logger.warn("UDP [{}] <- upstream не ответил для домена {}", clientIp, domain);

            try {
                sendRefusedResponse(socket, packet, message);

            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED из-за отсутствия upstream", clientIp, e);
            }

            return;
        }

        if (checkResponseBlacklist(response, domain)) {
            logger.info("UDP [{}] <- ответ заблокирован: {}", clientIp, domain);

            try {
                sendRefusedResponse(socket, packet, message);

            } catch (IOException e) {
                logger.error("UDP [{}]: не удалось отправить REFUSED для заблокированного ответа", clientIp, e);
            }

            return;
        }

        try {
            DatagramPacket replyPacket = getFormattedReply(response, packet);

            socket.send(replyPacket);

            logger.debug("UDP [{}] <- ответ отправлен для домена {}", clientIp, domain);

        } catch (IOException e) {
            logger.error("UDP [{}]: не удалось отправить ответ для домена {}", clientIp, domain, e);
        }
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

    private Message createRefusedResponse(Message query) {

        Message response = (Message) query.clone();
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setRcode(Rcode.REFUSED);

        return response;
    }

    private void handleTcpConnections(ServerSocket serverSocket) {

        while (!Thread.currentThread().isInterrupted()) {
            try {
                Socket socket = serverSocket.accept();
                String clientIp = socket.getInetAddress().getHostAddress();
                logger.info("TCP: принято соединение от {}", clientIp);
                workerPool.execute(() -> handleSingleTcpSession(socket));

            } catch (IOException e) {
                if (!Thread.currentThread().isInterrupted()) {
                    logger.debug("TCP accept error", e);
                }
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
                int len;

                try {
                    len = dataInput.readUnsignedShort();

                } catch (EOFException e) {
                    break;
                }

                if (len == 0) {
                    logger.warn("TCP [{}]: получен пакет нулевой длины", clientIp);

                    break;
                }

                byte[] requestData = new byte[len];

                dataInput.readFully(requestData);

                Message message;

                try {
                    message = new Message(requestData);

                } catch (WireParseException e) {
                    logger.debug("TCP [{}]: получен некорректный DNS-пакет", clientIp);

                    return;

                } catch (Exception e) {
                    logger.warn("TCP [{}]: ошибка чтения сообщения: {}", clientIp, e.getMessage());

                    continue;
                }

                String domain = "unknown";

                if (message.getQuestion() != null) {
                    domain = message.getQuestion().getName().toString();
                }

                logger.info("TCP [{}] -> DNS-запрос: {}", clientIp, domain);

                if (blacklist.isBlocked(domain, clientIp)) {
                    logger.info("TCP [{}] <- ЗАБЛОКИРОВАНО: {}", clientIp, domain);

                    sendTcpRefusedResponse(output, message);

                    continue;
                }

                Message response = forwardToResolver(message, clientIp);

                if (response == null) {
                    logger.warn("TCP [{}] <- upstream не ответил: {}", clientIp, domain);

                    sendTcpRefusedResponse(output, message);

                    continue;
                }

                if (checkResponseBlacklist(response, domain)) {
                    logger.info("TCP [{}] <- ответ заблокирован: {}", clientIp, domain);
                    sendTcpRefusedResponse(output, message);
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

    private void sendTcpRefusedResponse(OutputStream output, Message query) throws IOException {

        Message refused = createRefusedResponse(query);
        byte[] refusedBytes = refused.toWire();
        output.write(shortToBytes(refusedBytes.length));
        output.write(refusedBytes);
        output.flush();
    }

    private Message forwardToResolver(Message query, String clientIp) {

        String domain = query.getQuestion() != null ? query.getQuestion().getName().toString() : "unknown";

        for (Map.Entry<String, SimpleResolver> entry : resolvers.entrySet()) {

            String dns = entry.getKey();

            SimpleResolver resolver = entry.getValue();

            try {
                Message response = resolver.send(query);
                if (response != null) {
                    logger.info("Запрос [{}] от [{}] выполнен через {}", domain, clientIp, dns);
                    return response;
                }

            } catch (Exception e) {
                logger.trace("Ошибка upstream {}: {}", dns, e.getMessage());
            }
        }

        return null;
    }

    private DatagramPacket getFormattedReply(Message response, DatagramPacket requestPacket) {

        byte[] responseData = response.toWire();

        return new DatagramPacket(responseData, responseData.length, requestPacket.getAddress(), requestPacket.getPort());
    }

    private static byte[] shortToBytes(int value) {

        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException("Длина вне диапазона: " + value);
        }

        return new byte[]{(byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)
        };
    }
}