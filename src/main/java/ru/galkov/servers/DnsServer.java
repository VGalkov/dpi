package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.SimpleResolver;
import ru.galkov.llm.DnsAnomalyDetector;
import ru.galkov.util.BlacklistLoader;
import ru.galkov.util.BlacklistSnapshot;
import ru.galkov.util.DnsServerHelper;

import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import static ru.galkov.Main.getConfig;

public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);

    private final DnsAnomalyDetector dnsAnomalyDetector;
    private final ExecutorService workerPool;
    private final BlacklistLoader blacklist;
    private final Map<String, SimpleResolver> resolvers;
    private final DnsServerHelper.DnsRateLimiter rateLimiter;
    private final Object lifecycleLock = new Object();

    private volatile boolean running;
    private volatile DatagramSocket udpSocket;
    private volatile ServerSocket tcpListener;
    private volatile Thread tcpThread;

    public DnsServer(BlacklistLoader blacklist, DnsAnomalyDetector dnsAnomalyDetector) {
        this.blacklist = Objects.requireNonNull(blacklist);
        this.resolvers = createResolvers();
        this.dnsAnomalyDetector = dnsAnomalyDetector;
        this.rateLimiter = createRateLimiter();
        this.workerPool = DnsServerHelper.createWorkerPool(getConfig().getInt("dns.thread.num"));
    }

    public void run() {
        synchronized (lifecycleLock) {
            if (running) { logger.warn("DNS server уже запущен"); return; }
            running = true;
        }
        int port = getConfig().getInt("dns.local.port");
        logger.info("Запуск DNS форвардера на порту {}", port);
        try (DatagramSocket localUdpSocket = new DatagramSocket(port);
             ServerSocket localTcpListener = new ServerSocket(port)) {
            udpSocket = localUdpSocket;
            tcpListener = localTcpListener;
            startTcpAcceptor(localTcpListener);
            while (running) {
                DatagramPacket request = new DatagramPacket(new byte[4096], 4096);
                try { localUdpSocket.receive(request); } catch (SocketException e) {
                    if (!running) break;
                    throw e;
                }
                if (!running) break;
                InetAddress addr = request.getAddress();
                String clientIp = addr != null ? addr.getHostAddress() : "unknown";
                try { workerPool.execute(() -> processUdpRequest(localUdpSocket, request)); }
                catch (RuntimeException e) { logger.warn("DNS worker pool отклонил UDP-запрос от {}: {}", clientIp, e.getMessage()); }
            }
        } catch (IOException e) {
            if (running) logger.error("Критическая ошибка запуска DNS-сервера", e);
        } finally {
            running = false;
            udpSocket = null;
            tcpListener = null;
            DnsServerHelper.shutdownWorkerPool(workerPool);
            logger.info("DNS server завершил работу");
        }
    }

    public void stop() {
        synchronized (lifecycleLock) {
            if (!running) return;
            logger.info("Остановка DNS server начата");
            running = false;
            DnsServerHelper.closeQuietly(udpSocket);
            DnsServerHelper.closeQuietly(tcpListener);
            Thread currentTcpThread = tcpThread;
            if (currentTcpThread != null) currentTcpThread.interrupt();
        }
        DnsServerHelper.shutdownWorkerPool(workerPool);
        logger.info("Остановка DNS server завершена");
    }

    private void startTcpAcceptor(ServerSocket serverSocket) {
        tcpThread = new Thread(() -> handleTcpConnections(serverSocket), "DnsServer-TCP-Acceptor");
        tcpThread.setDaemon(false);
        tcpThread.start();
    }

    private void handleTcpConnections(ServerSocket serverSocket) {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                if (!running) { DnsServerHelper.closeQuietly(socket); break; }
                InetAddress addr = socket.getInetAddress();
                String clientIp = addr != null ? addr.getHostAddress() : "unknown";
                try { workerPool.execute(() -> handleSingleTcpSession(socket)); }
                catch (RuntimeException e) {
                    logger.warn("DNS worker pool отклонил TCP-соединение от {}: {}", clientIp, e.getMessage());
                    DnsServerHelper.closeQuietly(socket);
                }
            } catch (SocketException e) {
                if (running) logger.warn("TCP accept error: {}", e.getMessage());
                break;
            } catch (IOException e) {
                if (running) logger.debug("TCP accept error", e);
            }
        }
        logger.info("DNS TCP acceptor завершён");
    }

    private DnsServerHelper.DnsRateLimiter createRateLimiter() {
        boolean enabled = getConfig().getBoolean("dns.rate-limit.enabled");
        if (!enabled) {
            logger.info("DNS rate limit отключён");
            return DnsServerHelper.DnsRateLimiter.disabled();
        }
        int rps = getConfig().getInt("dns.rate-limit.requests-per-second");
        int burst = getConfig().getInt("dns.rate-limit.burst");
        int idle = getConfig().getInt("dns.rate-limit.client-idle-seconds");
        if (rps <= 0 || burst <= 0 || idle <= 0) throw new IllegalArgumentException("Rate limit params must be > 0");
        logger.info("DNS rate limit включён: rps={}, burst={}, idle={}", rps, burst, idle);
        return new DnsServerHelper.DnsRateLimiter(rps, burst, TimeUnit.SECONDS.toNanos(idle));
    }

    private Map<String, SimpleResolver> createResolvers() {
        Map<String, SimpleResolver> result = new LinkedHashMap<>();
        int timeout = getConfig().getInt("dns.timeout");
        for (String dns : getConfig().getList("dns.list")) {
            try {
                SimpleResolver resolver = new SimpleResolver(dns);
                resolver.setTimeout(Duration.ofSeconds(timeout));
                result.put(dns, resolver);
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException("Некорректный DNS upstream: " + dns, e);
            }
        }
        if (result.isEmpty()) throw new IllegalStateException("Список DNS upstream пуст");
        return Collections.unmodifiableMap(result);
    }

    private void processUdpRequest(DatagramSocket socket, DatagramPacket packet) {
        try {
            InetAddress addr = packet.getAddress();
            String clientIp = addr != null ? addr.getHostAddress() : "unknown";
            int length = packet.getLength();
            if (length == 0 || length > 4096) return;
            byte[] queryData = new byte[length];
            System.arraycopy(packet.getData(), packet.getOffset(), queryData, 0, length);
            Message query;
            try { query = new Message(queryData); } catch (Exception e) { return; }

            BlacklistSnapshot snapshot = blacklist.snapshot();
            String qname = DnsServerHelper.getQuestionName(query);

            if (!rateLimiter.tryAcquire(clientIp)) {
                try { DnsServerHelper.sendRefusedResponse(socket, packet, query); } catch (IOException e) { /* ignore */ }
                return;
            }

            if (DnsServerHelper.checkQueryBlacklist(query, snapshot).isPresent()) {
                try { DnsServerHelper.sendRefusedResponse(socket, packet, query); } catch (IOException e) { /* ignore */ }
                return;
            }

            Message response = forwardToResolver(query);
            if (response == null) {
                try { DnsServerHelper.sendRefusedResponse(socket, packet, query); } catch (IOException e) { /* ignore */ }
                return;
            }

            if (DnsServerHelper.checkResponseBlacklist(response, qname, blacklist) != null) {
                try { DnsServerHelper.sendRefusedResponse(socket, packet, query); } catch (IOException e) { /* ignore */ }
                return;
            }

            if (dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled()) {
                int queryType = query.getQuestion().getType();
                boolean isQuery = !query.getHeader().getFlag(Flags.QR);
                int opcode = query.getHeader().getOpcode();
                boolean isTruncated = query.getHeader().getFlag(Flags.TC);
                boolean recursionDesired = query.getHeader().getFlag(Flags.RD);
                int rcode = query.getHeader().getRcode();
                dnsAnomalyDetector.recordQuery(clientIp, qname, queryType, isQuery, opcode, isTruncated, recursionDesired, 0, rcode);
            }

            try {
                socket.send(DnsServerHelper.getFormattedReply(response, packet));
            } catch (IOException e) {
                if (running) logger.error("UDP [{}]: не удалось отправить ответ для домена {}", clientIp, qname, e);
            }
        } catch (Throwable t) {
            logger.error("Unexpected error in processUdpRequest", t);
        }
    }

    private void handleSingleTcpSession(Socket socket) {
        try {
            String clientIp = socket.getInetAddress().getHostAddress();
            try (Socket currentSocket = socket;
                 InputStream input = currentSocket.getInputStream();
                 OutputStream output = currentSocket.getOutputStream()) {
                DataInputStream dataInput = new DataInputStream(input);
                while (running && !currentSocket.isClosed()) {
                    int length;
                    try { length = dataInput.readUnsignedShort(); } catch (EOFException e) { break; }
                    if (length == 0) break;
                    byte[] requestData = new byte[length];
                    dataInput.readFully(requestData);
                    Message query;
                    try { query = new Message(requestData); } catch (Exception e) { continue; }

                    BlacklistSnapshot snapshot = blacklist.snapshot();
                    String qname = DnsServerHelper.getQuestionName(query);

                    if (!rateLimiter.tryAcquire(clientIp)) {
                        try { DnsServerHelper.sendTcpRefusedResponse(output, query); } catch (IOException e) { /* ignore */ }
                        continue;
                    }

                    if (DnsServerHelper.checkQueryBlacklist(query, snapshot).isPresent()) {
                        try { DnsServerHelper.sendTcpRefusedResponse(output, query); } catch (IOException e) { /* ignore */ }
                        continue;
                    }

                    Message response = forwardToResolver(query);
                    if (response == null) {
                        try { DnsServerHelper.sendTcpRefusedResponse(output, query); } catch (IOException e) { /* ignore */ }
                        continue;
                    }

                    if (DnsServerHelper.checkResponseBlacklist(response, qname, blacklist) != null) {
                        try { DnsServerHelper.sendTcpRefusedResponse(output, query); } catch (IOException e) { /* ignore */ }
                        continue;
                    }

                    if (dnsAnomalyDetector != null && dnsAnomalyDetector.isEnabled()) {
                        int queryType = query.getQuestion().getType();
                        boolean isQuery = !query.getHeader().getFlag(Flags.QR);
                        int opcode = query.getHeader().getOpcode();
                        boolean isTruncated = query.getHeader().getFlag(Flags.TC);
                        boolean recursionDesired = query.getHeader().getFlag(Flags.RD);
                        int rcode = query.getHeader().getRcode();
                        dnsAnomalyDetector.recordQuery(clientIp, qname, queryType, isQuery, opcode, isTruncated, recursionDesired, 0, rcode);
                    }

                    byte[] responseBytes = response.toWire();
                    output.write(DnsServerHelper.shortToBytes(responseBytes.length));
                    output.write(responseBytes);
                    output.flush();
                }
            } catch (IOException e) {
                if (running && !(e instanceof java.nio.channels.ClosedChannelException)) logger.debug("TCP [{}]: ошибка сессии", clientIp, e);
            }
        } catch (Throwable t) {
            logger.error("Unexpected error in handleSingleTcpSession", t);
        }
    }

    private Message forwardToResolver(Message query) {
        if (query == null || query.getQuestion() == null) return null;
        for (Map.Entry<String, SimpleResolver> entry : resolvers.entrySet()) {
            String dns = entry.getKey();
            SimpleResolver resolver = entry.getValue();
            try {
                Message response = resolver.send(query);
                if (response != null) {
                    if (response.getHeader().getFlag(Flags.TC)) {
                        response = forwardToResolverTcp(query, resolver);
                    }
                    return response;
                }
            } catch (Exception e) {
                logger.trace("Ошибка upstream {}: {}", dns, e.getMessage());
            }
        }
        return null;
    }

    private Message forwardToResolverTcp(Message query, SimpleResolver resolver) {
        try {
            resolver.setTCP(true);
            Message tcpResponse = resolver.send(query);
            resolver.setTCP(false);
            return tcpResponse;
        } catch (Exception e) {
            resolver.setTCP(false);
            return null;
        }
    }
}