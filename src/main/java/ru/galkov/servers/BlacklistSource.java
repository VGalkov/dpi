package ru.galkov.servers;


import java.io.IOException;
import java.util.List;

public interface BlacklistSource {
    List<String> loadRules() throws IOException;
}