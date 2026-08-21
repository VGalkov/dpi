package ru.galkov.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public final class IoUtil {

    private IoUtil() {
    }

    public static void closeQuietly(Socket s) {
        if (s == null || s.isClosed()) return;
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    public static void closeQuietly(DatagramSocket s) {
        if (s == null || s.isClosed()) return;
        try {
            s.close();
        } catch (Exception ignored) {
        }
    }

    public static void closeQuietly(ServerSocket s) {
        if (s == null || s.isClosed()) return;
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    public static byte[] readExactly(InputStream in, int len) throws IOException {
        byte[] buf = new byte[len];
        int total = 0;

        while (total < len) {
            int r = in.read(buf, total, len - total);
            if (r == -1) return null;
            total += r;
        }

        return buf;
    }

}