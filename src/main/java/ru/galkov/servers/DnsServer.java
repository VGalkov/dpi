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

            for (String dns : getConfig().getList("dns.list")) {
                try {
                    SimpleResolver resolver = new SimpleResolver(dns);
                    resolver.setTimeout(Duration.ofSeconds(timeout));

                    result.put(dns, resolver);

                    logger.info(
                            "DNS upstream инициализирован: {}",
                            dns
                    );
                } catch (UnknownHostException e) {
                    throw new IllegalArgumentException(
                            "Некорректный DNS upstream: " + dns,
                            e
                    );
                }
            }

            if (result.isEmpty()) {
                throw new IllegalStateException(
                        "Список DNS upstream пуст"
                );
            }

            return Collections.unmodifiableMap(result);
        }

        private boolean checkResponseBlacklist(
                Message response,
                String requestedDomain) {

            List<Record> records = new ArrayList<Record>();

            addRecords(records, response, Section.ANSWER);
            addRecords(records, response, Section.AUTHORITY);
            addRecords(records, response, Section.ADDITIONAL);

            for (Record record : records) {
                Name name = record.getName();

                if (name != null &&
                        blacklist.isBlockedDomain(name.toString())) {

                    logger.info(
                            "BLOCKED [Response]: запрещённый домен {} для запроса {}",
                            name,
                            requestedDomain
                    );
                    return true;
                }

                if (record instanceof ARecord) {
                    ARecord aRecord = (ARecord) record;

                    String ip = aRecord.getAddress()
                            .getHostAddress()
                            .toLowerCase(Locale.ROOT);

                    if (blacklist.isBlockedIp(ip)) {
                        logger.info(
                                "BLOCKED [Response]: запрещённый IPv4 {}",
                                ip
                        );
                        return true;
                    }
                }

                if (record instanceof AAAARecord) {
                    AAAARecord aaaaRecord = (AAAARecord) record;

                    String ip = aaaaRecord.getAddress()
                            .getHostAddress()
                            .toLowerCase(Locale.ROOT);

                    if (blacklist.isBlockedIp(ip)) {
                        logger.info(
                                "BLOCKED [Response]: запрещённый IPv6 {}",
                                ip
                        );
                        return true;
                    }
                }
            }

            return false;
        }


        private void addRecords(
                List<Record> target,
                Message message,
                int section) {

            List<Record> sectionRecords =
                    message.getSection(section);

            if (sectionRecords != null) {
                target.addAll(sectionRecords);
            }
        }

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
                message = new Message(queryData);
            } catch (WireParseException e) {
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

            if (blacklist.isBlocked(domain, clientIp)) {
                logger.info(
                        "UDP [{}] <- ЗАБЛОКИРОВАНО: {}",
                        clientIp,
                        domain
                );

                try {
                    sendRefusedResponse(socket, packet, queryData);
                } catch (IOException ioe) {
                    logger.error(
                            "UDP [{}]: Не удалось отправить REFUSED",
                            clientIp,
                            ioe
                    );
                }

                return;
            }

            Message response = forwardToResolver(message, clientIp);

            if (response != null) {
                if (checkResponseBlacklist(response, domain)) {
                    logger.info("UDP [{}] <- ЗАБЛОКИРОВАНО (ответ содержит запрещенный IP/Домен)", clientIp);
                    return;
                }

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

                    if (blacklist.isBlocked(domain, clientIp)) {
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
                            continue;
                        }

                        byte[] respBytes = response.toWire();
                        out.write(shortToBytes(respBytes.length));
                        out.write(respBytes);
                        out.flush();
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

        private Message forwardToResolver(
                Message query,
                String clientIp) {

            String domain = query.getQuestion() != null
                    ? query.getQuestion().getName().toString()
                    : "unknown";

            for (Map.Entry<String, SimpleResolver> entry
                    : resolvers.entrySet()) {

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
                    logger.trace(
                            "Ошибка upstream {}: {}",
                            dns,
                            e.getMessage()
                    );
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