package ru.galkov.blacklist_source;

import ru.galkov.util.BlacklistRule;

import java.io.IOException;
import java.util.List;
/**
 * [s0506777@yandex.ru](mailto:s0506777@yandex.ru) Galkov V.A.
 */
public interface BlacklistSource {
    List<BlacklistRule> loadRules() throws IOException;
}