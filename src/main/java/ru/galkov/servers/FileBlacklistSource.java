package ru.galkov.servers;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class FileBlacklistSource
        implements BlacklistSource {

    private final File file;

    public FileBlacklistSource(File file) {
        this.file = file;
    }

    @Override
    public List<String> loadRules() throws IOException {
        if (!file.isFile()) {
            return Collections.emptyList();
        }

        List<String> rules =
                new ArrayList<String>();

        try (BufferedReader reader =
                     new BufferedReader(
                             new InputStreamReader(
                                     new FileInputStream(file),
                                     StandardCharsets.UTF_8))) {

            String line;

            while ((line = reader.readLine()) != null) {
                String value = line.trim();

                if (value.isEmpty() ||
                        value.startsWith("#")) {
                    continue;
                }

                int commentIndex = value.indexOf('#');

                if (commentIndex >= 0) {
                    value = value
                            .substring(0, commentIndex)
                            .trim();
                }

                if (!value.isEmpty()) {
                    rules.add(value);
                }
            }
        }

        return rules;
    }
}