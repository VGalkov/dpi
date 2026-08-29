package ru.galkov.util;

import com.sun.jna.*;
import com.sun.jna.ptr.IntByReference;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketImpl;
import java.util.Arrays;

public final class OriginalDestination {

    private static final int SOL_IP = 0;
    private static final int SO_ORIGINAL_DST = 80;

    public interface CLibrary extends Library {
        CLibrary INSTANCE = Native.load("c", CLibrary.class);

        int getsockopt(int socket, int level, int optionName,
                       Pointer optionValue, IntByReference optionLen)
                throws LastErrorException;
    }

    public static class SockaddrIn extends Structure {
        public short sin_family;
        public short sin_port;
        public byte[] sin_addr = new byte[4];
        public byte[] sin_zero = new byte[8];

        @Override
        protected java.util.List<String> getFieldOrder() {
            return Arrays.asList("sin_family", "sin_port", "sin_addr", "sin_zero");
        }
    }

    public static InetSocketAddress getOriginalDestination(Socket socket) {
        if (socket == null) return null;

        int fd = getSocketFd(socket);
        if (fd < 0) {
            return null;
        }

        SockaddrIn addr = new SockaddrIn();
        addr.write();

        IntByReference len = new IntByReference(addr.size());

        try {
            int ret = CLibrary.INSTANCE.getsockopt(fd, SOL_IP, SO_ORIGINAL_DST,
                    addr.getPointer(), len);

            if (ret != 0) {
                return null;
            }

            addr.read();

            if (addr.sin_family == 2) {
                int port = Short.toUnsignedInt(Short.reverseBytes(addr.sin_port));
                InetAddress ip = InetAddress.getByAddress(addr.sin_addr);
                return new InetSocketAddress(ip, port);
            }
        } catch (Exception e) {
        }

        return null;
    }

    private static int getSocketFd(Socket socket) {
        try {
            Field implField = Socket.class.getDeclaredField("impl");
            implField.setAccessible(true);
            SocketImpl impl = (SocketImpl) implField.get(socket);

            Field fdField = SocketImpl.class.getDeclaredField("fd");
            fdField.setAccessible(true);
            Object fdObj = fdField.get(impl);

            if (fdObj instanceof java.io.FileDescriptor) {
                Field fdValField = fdObj.getClass().getDeclaredField("fd");
                fdValField.setAccessible(true);
                return fdValField.getInt(fdObj);
            }
        } catch (NoSuchFieldException | IllegalAccessException e) {
        }
        return -1;
    }

    private OriginalDestination() {
    }
}
