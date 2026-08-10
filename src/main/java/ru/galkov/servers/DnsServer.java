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
    private final ExecutorService workerPool = Executors.newFixedThreadPool(getConfig().getInt("dns.thread.num")); // Заменил на фиксированное число, если нет конфига

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
                workerPool.execute(() -> processUdpRequest(udpSocket, request));
            }
        } catch (IOException e) {
            logger.error("Критическая ошибка запуска DNS сервера", e);
        }
    }

    /* --------------------- UDP Handling ----------------------------------- */
    private void processUdpRequest(DatagramSocket socket, DatagramPacket packet) {
        try {
            int len = packet.getLength();
            if (len == 0 || len > 4096) {
                logger.warn("Странный пакет от {}, длина {}", packet.getAddress(), len);
                return;
            }

            byte[] queryData = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + len);

            Message message;
            try {
                message = new Message(queryData);
            } catch (WireParseException e) {
                logger.debug("Битый DNS-пакет от {}: {}", packet.getAddress(), e.getMessage());
                sendRefusedResponse(socket, packet, queryData);
                return;
            } catch (Exception e) {
                logger.warn("Неизвестный формат пакета", e);
                return;
            }

            Message response = forwardToResolver(message);
            if (response != null) {
                socket.send(getFormatedReply(response, packet));
            } else {
                sendRefusedResponse(socket, packet, queryData);
            }

        } catch (Exception e) {
            logger.error("Ошибка обработки UDP", e);
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
                workerPool.execute(() -> handleSingleTcpSession(socket));
            } catch (IOException e) {
                if (!Thread.currentThread().isInterrupted()) {
                    logger.debug("Ошибка принятия TCP соединения", e);
                }
            }
        }
    }

    private void handleSingleTcpSession(Socket socket) {
        try (Socket s = socket;
             InputStream in = s.getInputStream();
             OutputStream out = s.getOutputStream()) {

            DataInputStream din = new DataInputStream(in);
            while (!s.isClosed()) {
                int len = din.readUnsignedShort();
                byte[] requestData = new byte[len];
                din.readFully(requestData);

                Message message = new Message(requestData);

                // --- ГЛАВНОЕ ИЗМЕНЕНИЕ: Убрана вся логика проверок и подмен ---

                Message response = forwardToResolver(message);

                if (response != null) {
                    byte[] respBytes = response.toWire();
                    out.write(shortToBytes(respBytes.length));
                    out.write(respBytes);
                    out.flush();
                } else {
                    // Отправляем REFUSED в TCP формате (длина + сообщение)
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
                logger.debug("Ошибка в TCP сессии", e);
            }
        }
    }

    private Message forwardToResolver(Message query) {

        String[] upstreams;
        upstreams = getConfig().getSet("dns.list").toArray(new String[0]);
        int timeout = getConfig().getInt("dns.timeout");

        for (String dns : upstreams) {
            try {
                SimpleResolver resolver = new SimpleResolver(dns);
                resolver.setTimeout(Duration.ofSeconds(timeout));
                Message response = resolver.send(query);

                if (response != null) {
                    logger.trace("Запрос {} выполнен через {}", query.getQuestion(), dns);
                    return response;
                }
            } catch (IOException e) {
                logger.trace("Сервер {} недоступен для запроса {}: {}", dns, query.getQuestion(), e.getMessage());
            } catch (Exception e) {
                logger.trace("Ошибка при запросе к {}: {}", dns, e.getMessage());
            }
        }

        return null; // Ни один сервер не ответил
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