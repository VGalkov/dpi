package ru.galkov.util;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.text.DecimalFormat;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Интеграционные тесты ТОЛЬКО для HTTP Proxy компонента DPI.
 *
 * ЛОГИКА ПРОВЕРКИ:
 * Мы проверяем, что прокси корректно маршрутизирует запросы.
 * Важно: Тест не зависит от решения LLM. Если домен не в черном списке,
 * прокси обязан вернуть контент (статус 2xx/3xx), даже если LLM считает его подозрительным.
 * Если прокси блокирует запрос без причины — тест должен упасть.
 */
public class DpiProxyIntegrationTest {

    private static final Logger logger = LoggerFactory.getLogger(DpiProxyIntegrationTest.class);
    private static final DecimalFormat DF = new DecimalFormat("#,###.##");

    // Конфигурация прокси
    private static final String PROXY_HOST = "127.0.0.1";
    private static final int PROXY_PORT = 3128;
    private static final int HTTP_TIMEOUT_MS = 5000;

    @BeforeAll
    public static void beforeAll() {
        logger.info("===============================================================================");
        logger.info("   STARTING HTTP PROXY INTEGRATION TESTS");
        logger.info("   Target Proxy: {}:{}", PROXY_HOST, PROXY_PORT);
        logger.info("   Policy Check: Allowed requests MUST be proxied regardless of LLM decision.");
        logger.info("===============================================================================");
    }

    /**
     * ТЕСТ 1: Базовая функциональность (Single GET Request)
     * Проверяет, что прокси жив и способен отдать контент.
     */

    @Test
    public void testProxyBasicGetRequest() throws Exception {
        String testName = "BASIC: Single GET Request";
        logger.info("[RUNNING] {}", testName);

        if (!isProxyRunning()) {
            fail("CRITICAL: HTTP proxy is not running on " + PROXY_HOST + ":" + PROXY_PORT);
        }

        // Целевой домен для теста.
        // ВАЖНО: Для отладки лучше использовать простой домен без сложной SSL/HSTS логики,
        // если прокси еще не полностью готов к HTTPS. Но если curl работает на google.com, оставим rbc.ru или google.com.
        String targetUrlStr = "http://rbc.ru";
        URL url = new URL(targetUrlStr);

        logger.debug("TEST CONFIG: Target URL: {}, Proxy: {}:{}", targetUrlStr, PROXY_HOST, PROXY_PORT);

        long startTime = System.nanoTime();
        HttpURLConnection conn = null;
        String serverErrorMessage = "No error body returned";
        int responseCode = -1;

        try {
            // Создаем соединение через прокси
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(PROXY_HOST, PROXY_PORT));
            conn = (HttpURLConnection) url.openConnection(proxy);

            // Настройки таймаутов
            conn.setConnectTimeout(HTTP_TIMEOUT_MS);
            conn.setReadTimeout(HTTP_TIMEOUT_MS);

            // Дополнительные заголовки, чтобы эмулировать обычный браузер и избежать блокировок по User-Agent
            conn.setRequestMethod("GET");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
            conn.setRequestProperty("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");

            conn.setInstanceFollowRedirects(true);

            // Получаем код ответа. Это может выбросить IOException, если сервер сразу рвет соединение
            responseCode = conn.getResponseCode();

            logger.debug("Received HTTP Status Code: {}", responseCode);

            // Попытка прочитать тело ответа (успех или ошибка)
            InputStream inputStream;
            if (responseCode >= 200 && responseCode < 400) {
                inputStream = conn.getInputStream();
            } else {
                // Для ошибок (4xx, 5xx) используем getErrorStream()
                inputStream = conn.getErrorStream();
            }

            if (inputStream != null) {
                byte[] buffer = new byte[2048]; // Увеличили буфер
                int bytesRead = inputStream.read(buffer);
                if (bytesRead > 0) {
                    serverErrorMessage = new String(buffer, 0, bytesRead, java.nio.charset.StandardCharsets.UTF_8);
                    // Обрезаем длинный ответ для логов, но оставляем первые 200 символов
                    if (serverErrorMessage.length() > 200) {
                        serverErrorMessage = serverErrorMessage.substring(0, 200) + "...";
                    }
                    logger.debug("Server Response Body: {}", serverErrorMessage);
                    System.out.println("=== DEBUG BODY FROM PROXY ===");
                    System.out.println(serverErrorMessage);
                    System.out.println("===============================");
                }
            }

        } catch (IOException e) {
            logger.error("Connection failed entirely (SocketException, Connection reset): {}", e.getMessage());
            serverErrorMessage = e.getClass().getSimpleName() + ": " + e.getMessage();
            throw e; // Пробрасываем дальше, чтобы тест упал явно
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }

        long endTime = System.nanoTime();
        int latencyMs = (int) ((endTime - startTime) / 1_000_000);

        // ГЛАВНОЕ УТВЕРЖДЕНИЕ
        // Теперь сообщение об ошибке содержит текст, который прислал сам прокси!
        assertTrue(
                responseCode >= 200 && responseCode < 400,
                "CRITICAL: Proxy blocked allowed request. Status Code: " + responseCode +
                        ". Expected 2xx or 3xx. \nPROXY ERROR DETAIL: \"" + serverErrorMessage + "\""
        );

        logger.info("[PASS] {} | Status: {} | Latency: {} ms", testName, responseCode, latencyMs);
        printDetailedStats(testName, 1, 0, latencyMs, latencyMs);
    }

    /**
     * Утилита: Вывод детальной сводной статистики в консоль
     */
    private void printDetailedStats(String testName, int success, int errors, int avgLatency, int totalTimeMs) {
        logger.info("");
        logger.info("=== DETAILED STATISTICS REPORT: {} ===", testName);
        logger.info("| Metric                | Value          |");
        logger.info("|-----------------------|----------------|");
        logger.info("| Status                | {}             |", errors == 0 ? "PASSED" : "FAILED");
        logger.info("| Success Count         | {}             |", success);
        logger.info("| Error Count           | {}             |", errors);
        logger.info("| Avg Latency           | {} ms          |", avgLatency);
        logger.info("| Total Time (sum)      | {} ms          |", totalTimeMs);
        if (success > 0 && totalTimeMs > 0) {
            logger.info("| Efficiency            | {} req/sec     |", (success * 1000) / totalTimeMs);
        } else {
            logger.info("| Efficiency            | N/A            |");
        }
        logger.info("========================================\n");
    }

    /**
     * Проверка доступности прокси перед запуском тестов
     */
    private boolean isProxyRunning() {
        try (java.net.Socket socket = new java.net.Socket(PROXY_HOST, PROXY_PORT)) {
            return true;
        } catch (java.io.IOException e) {
            return false;
        }
    }
}
