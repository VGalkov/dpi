package ru.galkov.integration;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ProxyDnsIntegrationTest {
    private static final String HOST = System.getProperty("dpi.test.host", "127.0.0.1");
    private static final int PROXY_PORT = Integer.getInteger("dpi.test.proxy-port", 8888);
    private static final int DNS_PORT = Integer.getInteger("dpi.test.dns-port", 53);
    private static final String DOMAIN = System.getProperty("dpi.test.domain", "www.cofe.ru");
    private static final long TIMEOUT_SECONDS = Long.getLong("dpi.test.timeout-seconds", 20L);
    private static final boolean ENABLED = Boolean.parseBoolean(System.getProperty("dpi.integration", "false"));

    @BeforeAll
    static void beforeAll() {
        line();
        log("START ProxyDnsIntegrationTest");
        log("Integration enabled: " + ENABLED);
        log("Host: " + HOST);
        log("Proxy endpoint: http://" + HOST + ":" + PROXY_PORT);
        log("DNS endpoint: " + HOST + ":" + DNS_PORT);
        log("Domain: " + DOMAIN);
        log("Process timeout: " + TIMEOUT_SECONDS + " seconds");
        log("Current directory: " + System.getProperty("user.dir"));
        log("PATH available: " + System.getenv("PATH"));
        line();
    }

    @Test
    @DisplayName("HTTPS request through local proxy is blocked")
    void httpsRequestIsBlocked(TestInfo info) throws Exception {
        start(info);
        requireEnabled();

        List<String> command = List.of(
                "curl.exe", "-v", "--noproxy", "", "--proxy",
                "http://" + HOST + ":" + PROXY_PORT,
                "--connect-timeout", "5", "--max-time", "15",
                "https://" + DOMAIN + "/"
        );

        runAndAssertBlocked(command, "HTTPS proxy request");
        finish(info);
    }

    @Test
    @DisplayName("HTTP request through local proxy is blocked")
    void httpRequestIsBlocked(TestInfo info) throws Exception {
        start(info);
        requireEnabled();

        List<String> command = List.of(
                "curl.exe", "-v", "--noproxy", "", "--proxy",
                "http://" + HOST + ":" + PROXY_PORT,
                "--connect-timeout", "5", "--max-time", "15",
                "http://" + DOMAIN + "/"
        );

        runAndAssertBlocked(command, "HTTP proxy request");
        finish(info);
    }

    @Test
    @DisplayName("DNS request through local DNS is blocked")
    void dnsRequestIsBlocked(TestInfo info) throws Exception {
        start(info);
        requireEnabled();

        List<String> command = List.of(
                "nslookup.exe", DOMAIN, HOST
        );

        runAndAssertBlocked(command, "DNS request");
        finish(info);
    }

    private static void runAndAssertBlocked(
            List<String> command,
            String name
    ) throws Exception {
        log("Preparing: " + name);
        log("Command: " + formatCommand(command));
        log("Starting external process...");

        ProcessResult result = execute(command);

        log("External process finished");
        log("Exit code: " + result.exitCode());
        log("Timed out: " + result.timedOut());
        log("Output length: " + result.output().length() + " characters");
        log("----- BEGIN PROCESS OUTPUT -----");
        log(result.output().isBlank() ? "<empty output>" : result.output());
        log("----- END PROCESS OUTPUT -----");

        String normalized = result.output().toLowerCase(Locale.ROOT);
        boolean blockSignal = hasBlockSignal(normalized);
        boolean successPayload = hasSuccessfulPayload(normalized, result);

        log("Block signal detected: " + blockSignal);
        log("Successful payload detected: " + successPayload);
        log("Decision: " + (blockSignal || result.timedOut() || result.exitCode() != 0 ? "BLOCKED" : "NOT BLOCKED"));

        assertTrue(
                result.timedOut()
                        || result.exitCode() != 0
                        || blockSignal
                        || !successPayload,
                name + " was not blocked.\n" + result.output()
        );
    }

    private static boolean hasBlockSignal(String output) {
        return output.contains("403")
                || output.contains("forbidden")
                || output.contains("blocked")
                || output.contains("proxy error")
                || output.contains("proxy connect aborted")
                || output.contains("connection refused")
                || output.contains("connection reset")
                || output.contains("connection closed")
                || output.contains("server failed")
                || output.contains("nxdomain")
                || output.contains("non-existent domain")
                || output.contains("name does not exist")
                || output.contains("timed out")
                || output.contains("timeout")
                || output.contains("refused");
    }

    private static boolean hasSuccessfulPayload(
            String output,
            ProcessResult result
    ) {
        if (result.exitCode() != 0 || result.timedOut()) {
            return false;
        }

        return output.contains("<html")
                || output.contains("http/1.1 200")
                || output.contains("http/2 200")
                || output.contains("name:")
                || output.matches("(?s).*\\baddress:\s+\\d{1,3}(?:\\.\\d{1,3}){3}\\b.*");
    }

    private static ProcessResult execute(
            List<String> command
    ) throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);

        log("ProcessBuilder created");
        log("redirectErrorStream=true");
        log("Waiting up to " + TIMEOUT_SECONDS + " seconds");

        Process process = builder.start();
        log("Process started, pid=" + process.pid());

        StringBuilder output = new StringBuilder();
        Thread reader = new Thread(
                () -> readOutput(process, output),
                "integration-process-output-reader"
        );
        reader.start();
        log("Output reader thread started");

        boolean finished = process.waitFor(
                TIMEOUT_SECONDS,
                TimeUnit.SECONDS
        );

        if (!finished) {
            log("Process timeout reached; destroying process");
            process.destroy();

            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                log("Graceful destroy failed; destroying forcibly");
                process.destroyForcibly();
            }

            reader.join(2_000);
            return new ProcessResult(-1, output.toString(), true);
        }

        log("Process exited normally");
        reader.join(2_000);

        return new ProcessResult(
                process.exitValue(),
                output.toString(),
                false
        );
    }

    private static void readOutput(
            Process process,
            StringBuilder output
    ) {
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        process.getInputStream(),
                        StandardCharsets.UTF_8
                )
        )) {
            String line;
            while ((line = reader.readLine()) != null) {
                synchronized (output) {
                    output.append(line)
                            .append(System.lineSeparator());
                }
                log("[process] " + line);
            }
        } catch (IOException e) {
            synchronized (output) {
                output.append("[reader error] ")
                        .append(e.getMessage())
                        .append(System.lineSeparator());
            }
            log("Output reader error: " + e.getMessage());
        }
    }

    private static void requireEnabled() {
        log("Checking dpi.integration flag");
        assumeTrue(
                ENABLED,
                "Integration tests disabled; use -Ddpi.integration=true"
        );
        log("Integration mode enabled");
    }

    private static String formatCommand(List<String> command) {
        List<String> parts = new ArrayList<>(command.size());
        for (String value : command) {
            parts.add(value.contains(" ") ? '"' + value + '"' : value);
        }
        return String.join(" ", parts);
    }

    private static void start(TestInfo info) {
        line();
        log("TEST START: " + info.getDisplayName());
        log("Test method: " + info.getTestMethod().map(m -> m.getName()).orElse("unknown"));
    }

    private static void finish(TestInfo info) {
        log("TEST PASS: " + info.getDisplayName());
        line();
    }

    private static void line() {
        log("=".repeat(90));
    }

    private static void log(String message) {
        System.out.println("[ProxyDnsIntegrationTest] " + message);
    }

    private record ProcessResult(
            int exitCode,
            String output,
            boolean timedOut
    ) {
    }
}
