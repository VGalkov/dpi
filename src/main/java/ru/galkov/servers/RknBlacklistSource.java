package ru.galkov.servers;

import java.io.IOException;
import java.util.List;

public final class RknBlacklistSource
        implements BlacklistSource {

    @Override
    public List<String> loadRules() throws IOException {

        /*
         * Здесь будет:
         * 1. SOAP/XML-запрос к сервису РКН.
         * 2. Авторизация сертификатом, если требуется.
         * 3. Разбор XML.
         * 4. Преобразование записей в домены и IP.
         */

        throw new UnsupportedOperationException(
                "Нужен WSDL и пример XML-ответа РКН"
        );
    }
}