package ru.galkov.blacklist_source;


import java.io.IOException;
import java.util.List;

public interface BlacklistSource {
    List<String> loadRules() throws IOException;
}