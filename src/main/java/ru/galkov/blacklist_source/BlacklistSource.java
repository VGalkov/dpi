package ru.galkov.blacklist_source;

import java.io.IOException;
import java.util.List;
/**
 * s0506777@yandex.ru Galkov V.A.
 */
public interface BlacklistSource {
    List<String> loadRules() throws IOException;
}