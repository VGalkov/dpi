package ru.galkov.util;

import org.xbill.DNS.*;
import org.xbill.DNS.Record;

import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class DnsServerHelper {

    private DnsServerHelper() {}


    public static byte[] shortToBytes(int value) {
        if (value < 0 || value > 0xFFFF)
            throw new IllegalArgumentException(LocaleUtil.getString("dns_helper_length_out_of_range", value));

        return new byte[]{(byte) ((value >> 8) & 0xFF), (byte) (value & 0xFF)};
    }

    public static String getQuestionName(Message message) {
        if (message == null) return "unknown";
        Record question = message.getQuestion();
        if (question == null || question.getName() == null) return "unknown";
        return question.getName().toString();
    }

    public static String extractIpv4FromPtrQuery(String ptrName) {
        if (ptrName == null) return null;
        String name = ptrName.toLowerCase(Locale.ROOT);
        if (!name.endsWith(".in-addr.arpa.")) return null;
        String reversedIp = name.substring(0, name.length() - ".in-addr.arpa.".length());
        String[] parts = reversedIp.split("\\.");
        if (parts.length != 4) return null;
        String ip = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
        return HostNormalizer.isIpLiteralFast(ip) ? ip : null;
    }

    public static String extractIpv6FromPtrQuery(String ptrName) {
        if (ptrName == null) return null;
        String name = ptrName.toLowerCase(Locale.ROOT);
        if (!name.endsWith(".ip6.arpa.")) return null;
        String reversedNibbles = name.substring(0, name.length() - ".ip6.arpa.".length());
        String[] nibbles = reversedNibbles.split("\\.");
        if (nibbles.length != 32) return null;

        StringBuilder hex = new StringBuilder(32);

        for (int i = nibbles.length - 1; i >= 0; i--) {
            String nibble = nibbles[i];
            if (nibble.length() != 1 || Character.digit(nibble.charAt(0), 16) < 0) return null;
            hex.append(nibble);
        }

        StringBuilder ipv6 = new StringBuilder(39);

        for (int i = 0; i < hex.length(); i += 4) {
            if (i > 0) ipv6.append(':');
            ipv6.append(hex, i, i + 4);
        }

        return ipv6.toString();
    }

    public static Optional<String> checkQueryBlacklist(Message query, BlacklistSnapshot snapshot) {
        if (query == null || snapshot == null) return Optional.empty();

        Record question = query.getQuestion();

        if (question == null || question.getName() == null)
            return Optional.empty();

        String qname = question.getName().toString();

        if (snapshot.checkDomain(qname).isBlocked())
            return Optional.of(LocaleUtil.getString("dns_helper_blocked_domain", qname));

        String ipv4 = extractIpv4FromPtrQuery(qname);

        if (ipv4 != null && snapshot.checkIp(ipv4).isBlocked())
            return Optional.of(LocaleUtil.getString("dns_helper_blocked_ipv4", ipv4));

        String ipv6 = extractIpv6FromPtrQuery(qname);
        if (ipv6 != null && snapshot.checkIp(ipv6).isBlocked())
            return Optional.of(LocaleUtil.getString("dns_helper_blocked_ipv6", ipv6));

        return Optional.empty();
    }

    public static String checkResponseBlacklist(Message response, String requestedDomain, BlacklistLoader blacklist) {
        if (response == null || blacklist == null) return null;
        BlacklistSnapshot snapshot = blacklist.snapshot();

        if (snapshot == null) return null;
        int[] sections = {Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL};

        for (int section : sections) {
            List<Record> records = response.getSection(section);

            if (records == null || records.isEmpty()) continue;
            for (Record record : records) {
                String reason = checkRecordBlacklist(record, section, requestedDomain, snapshot);
                if (reason != null) return reason;
            }
        }

        return null;
    }

    private static String checkRecordBlacklist(
            Record record,
            int section,
            String requestedDomain,
            BlacklistSnapshot snapshot
    ) {
        if (record == null || snapshot == null) return null;
        Name ownerName = record.getName();
        if (ownerName != null && snapshot.checkDomain(ownerName.toString()).isBlocked()) {
            return LocaleUtil.getString(
                    "dns_helper_blocked_owner_domain",
                    ownerName,
                    Section.string(section),
                    requestedDomain
            );
        }

        if (record instanceof ARecord aRecord) {
            String ip = aRecord.getAddress().getHostAddress();

            if (snapshot.checkIp(ip).isBlocked())
                return LocaleUtil.getString("dns_helper_blocked_ipv4_a_record", ip, Section.string(section));

            return null;
        }

        if (record instanceof AAAARecord aaaaRecord) {
            String ip = aaaaRecord.getAddress().getHostAddress();

            if (snapshot.checkIp(ip).isBlocked()) {
                return LocaleUtil.getString(
                        "dns_helper_blocked_ipv6_aaaa_record",
                        ip,
                        Section.string(section)
                );
            }

            return null;
        }

        Name targetName = extractTargetName(record);

        if (targetName != null && snapshot.checkDomain(targetName.toString()).isBlocked()) {
            return LocaleUtil.getString(
                    "dns_helper_blocked_target_domain",
                    targetName,
                    record.getClass().getSimpleName(),
                    Section.string(section)
            );
        }

        return null;
    }

    private static Name extractTargetName(Record record) {
        if (record instanceof CNAMERecord) return ((CNAMERecord) record).getTarget();
        if (record instanceof DNAMERecord) return ((DNAMERecord) record).getTarget();
        if (record instanceof PTRRecord) return ((PTRRecord) record).getTarget();
        if (record instanceof NSRecord) return ((NSRecord) record).getTarget();
        if (record instanceof MXRecord) return ((MXRecord) record).getTarget();
        if (record instanceof SRVRecord) return ((SRVRecord) record).getTarget();

        return null;
    }

    public static Message createRefusedResponse(Message query) {
        if (query == null) throw new IllegalArgumentException(LocaleUtil.getString("dns_helper_query_null"));
        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        response.getHeader().setRcode(Rcode.REFUSED);
        if (query.getQuestion() != null) response.addRecord(query.getQuestion(), Section.QUESTION);

        return response;
    }

    public static void sendRefusedResponse(
            DatagramSocket socket,
            DatagramPacket originalPacket,
            Message query
    ) throws IOException {
        if (socket == null || originalPacket == null || query == null)
            throw new IllegalArgumentException(LocaleUtil.getString("dns_helper_send_refused_args"));

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

    public static void sendTcpRefusedResponse(OutputStream output, Message query) throws IOException {
        if (output == null || query == null) throw new IllegalArgumentException(LocaleUtil.getString("dns_helper_send_tcp_refused_args"));

        Message refused = createRefusedResponse(query);
        byte[] refusedBytes = refused.toWire();
        output.write(shortToBytes(refusedBytes.length));
        output.write(refusedBytes);
        output.flush();
    }
}