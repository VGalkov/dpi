package ru.galkov.servers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.*;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import static ru.galkov.Main.getConfig;

public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);
    private final ExecutorService workerPool = Executors.newFixedThreadPool(getConfig().getInt("dns.thread.num"));

    public DnsServer() {
    }

    /**
     * Запускает сервер. Блокирует поток навсегда.
     */
    public void run() {
        int port = getConfig().getShort("dns.local.port");
        logger.info("Запуск чистого DNS форвардера на порту {}", port);

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

                // ЛОГ: Пришел UDP запрос
                String clientIp = request.getAddress().getHostAddress();
                logger.debug("UDP: Получен пакет от клиента {}", clientIp);

                workerPool.execute(() -> processUdpRequest(udpSocket, request));
            }
        } catch (IOException e) {
            logger.error("Критическая ошибка запуска DNS сервера", e);
        }
    }

    /* --------------------- UDP Handling ----------------------------------- */
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
                logger.warn("UDP [{}]: Битый DNS-пакет (WireParseException): {}", clientIp, e.getMessage());
                sendRefusedResponse(socket, packet, queryData);
                return;
            } catch (Exception e) {
                logger.warn("UDP [{}]: Неизвестный формат пакета: {}", clientIp, e.getMessage());
                return;
            }

            // ЛОГ: Извлекаем домен для отображения
            String domain = "unknown";
            if (message.getQuestion() != null) {
                domain = message.getQuestion().getName().toString();
            }

            // ЛОГ: Начало обработки запроса
            logger.info("UDP [{}] -> Запрос: {}", clientIp, domain);

            Message response = forwardToResolver(message, clientIp);

            if (response != null) {
                socket.send(getFormatedReply(response, packet));
                // ЛОГ: Успешный ответ
                logger.info("UDP [{}] <- Ответ отправлен для: {}", clientIp, domain);
            } else {
                // ЛОГ: Ошибка форвардинга
                logger.warn("UDP [{}] <- Ни один upstream не ответил для: {}. Возвращаем REFUSED.", clientIp, domain);
                sendRefusedResponse(socket, packet, queryData);
            }

        } catch (Exception e) {
            logger.error("UDP [{}]: Критическая ошибка обработки запроса", clientIp, e);
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

                // ЛОГ: Новое TCP соединение
                logger.info("TCP: Принято соединение от {}", clientIp);

                workerPool.execute(() -> handleSingleTcpSession(socket));
            } catch (IOException e) {
                if (!Thread.currentThread().isInterrupted()) {
                    logger.debug("Ошибка принятия TCP соединения", e);
                }
            }
        }
    }

    private void handleSingleTcpSession(Socket socket) {
        String clientIp = socket.getInetAddress().getHostAddress();
        try (Socket s = socket;
             InputStream in = s.getInputStream();
             OutputStream out = s.getOutputStream()) {

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

                // ЛОГ: Запрос внутри TCP сессии
                logger.info("TCP [{}] -> Запрос: {}", clientIp, domain);

                Message response = forwardToResolver(message, clientIp);

                if (response != null) {
                    byte[] respBytes = response.toWire();
                    out.write(shortToBytes(respBytes.length));
                    out.write(respBytes);
                    out.flush();
                    // ЛОГ: Успех в TCP
                    logger.info("TCP [{}] <- Ответ отправлен для: {}", clientIp, domain);
                } else {
                    // ЛОГ: Отказ в TCP
                    logger.warn("TCP [{}] <- Ни один upstream не ответил для: {}. Возвращаем REFUSED.", clientIp, domain);

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
                logger.debug("TCP [{}]: Ошибка в сессии", clientIp, e);
            }
        } finally {
            // ЛОГ: Завершение сессии
            logger.info("TCP: Сессия с {} завершена", clientIp);
        }
    }

    // Добавлен аргумент clientIp для передачи в лог, логика внутри не изменена
    private Message forwardToResolver(Message query, String clientIp) {
        String[] upstreams;
        upstreams = getConfig().getSet("dns.list").toArray(new String[0]);
        int timeout = getConfig().getInt("dns.timeout");

        for (String dns : upstreams) {
            try {
                SimpleResolver resolver = new SimpleResolver(dns);
                resolver.setTimeout(Duration.ofSeconds(timeout));
                Message response = resolver.send(query);

                if (response != null) {
                    String domain = query.getQuestion() != null ? query.getQuestion().getName().toString() : "unknown";
                    // ЛОГ: Какой сервер сработал
                    logger.info("Запрос [{}] от [{}] успешно выполнен через upstream: {}", domain, clientIp, dns);
                    return response;
                }
            } catch (IOException e) {
                // Оставляем trace для ошибок соединения с upstream, чтобы не засорять консоль
                logger.trace("Сервер {} недоступен для запроса {} от {}: {}", dns, query.getQuestion(), clientIp, e.getMessage());
            } catch (Exception e) {
                logger.trace("Ошибка при запросе к {}: {}", dns, e.getMessage());
            }
        }

        return null;
    }

    // Перегрузка для совместимости со старыми вызовами (если вдруг где-то вызывается без IP)
    private Message forwardToResolver(Message query) {
        return forwardToResolver(query, "unknown");
    }

    private DatagramPacket getFormatedReply(Message response, DatagramPacket packet) {
        byte[] respData = response.toWire();
        return new DatagramPacket(
                respData,
                respData.length,
                packet.getAddress(),
                packet.getPort()
        );
    }

    private static byte[] shortToBytes(int value) {
        if (value < 0 || value > 0xFFFF)
            throw new IllegalArgumentException("Длина вне диапазона: " + value);
        return new byte[]{
                (byte) ((value >> 8) & 0xFF),
                (byte) (value & 0xFF)
        };
    }
}