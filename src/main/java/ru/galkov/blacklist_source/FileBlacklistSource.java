package ru.galkov.blacklist_source;

import ru.galkov.util.BlacklistRule;
import ru.galkov.util.LocaleUtil;

import java.io.*;
import java.net.URL;
import java.util.List;

/**
 * s0506777@yandex.ru Galkov V.A.
 */
public final class FileBlacklistSource extends AbstractBlacklistSource {
    private final File file;

    public FileBlacklistSource(File file) {
        if (file == null) throw new IllegalArgumentException(LocaleUtil.getString("file_blacklist_cannot_be_null"));
        this.file = file;
    }

    @Override
    public List<BlacklistRule> loadRules() throws IOException {
        InputStream input = openInputStream();
        List<BlacklistRule> rules = loadFromStream(input, "LocalFile");
        logger.info(LocaleUtil.getString("local_blacklist_loaded"), file.getPath(), rules.size());
        return rules;
    }

    private InputStream openInputStream() throws IOException {
        if (file.isFile()) {
            logger.info("File source found: file={}", file.getAbsolutePath());
            return new FileInputStream(file);
        }

        String resourceName = file.getPath().replace('\\', '/').replaceFirst("^/", "");
        URL resource = FileBlacklistSource.class.getClassLoader().getResource(resourceName);
        if (resource != null) {
            logger.info(LocaleUtil.getString("blacklist_in_classpath"), resource.toExternalForm());
            return resource.openStream();
        }

        throw new FileNotFoundException(LocaleUtil.getString("blacklist_not_found") + file.getAbsolutePath());
    }

    @Override
    public String toString() {
        return "FileBlacklistSource{file=" + file.getParentFile() + '}';
    }
}