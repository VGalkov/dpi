package ru.galkov.servers;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

public final class RknRequestSignerInfo implements RknRequestSigner {
    private final Path certificateFile;
    private final Path keyStoreFile;
    private final char[] keyStorePassword;
    private final String keyAlias;
    private final String signatureAlgorithm;

    public RknRequestSignerInfo(Path certificateFile, Path keyStoreFile, char[] keyStorePassword, String keyAlias, String signatureAlgorithm) {
        this.certificateFile = certificateFile;
        this.keyStoreFile = keyStoreFile;
        this.keyStorePassword = keyStorePassword.clone();
        this.keyAlias = keyAlias;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public byte[] sign(byte[] data) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        X509Certificate certificate = loadCertificate();
        PrivateKey privateKey = loadPrivateKey();

        if (!certificate.getPublicKey().getAlgorithm().equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalStateException("Сертификат и закрытый ключ используют разные алгоритмы");
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(privateKey);
        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, certificate));
        generator.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));
        CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(data), false);

        return signedData.getEncoded();
    }

    private X509Certificate loadCertificate() throws Exception {
        try (InputStream input = Files.newInputStream(certificateFile)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(input);
        }
    }

    private PrivateKey loadPrivateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (InputStream input = Files.newInputStream(keyStoreFile)) {
            keyStore.load(input, keyStorePassword);
        }

        String alias = keyAlias;

        if (alias == null || alias.isBlank()) {
            alias = keyStore.aliases().nextElement();
        }

        Key key = keyStore.getKey(alias, keyStorePassword);

        if (!(key instanceof PrivateKey)) {
            throw new IllegalStateException("В PKCS#12 не найден закрытый ключ для alias: " + alias);
        }

        return (PrivateKey) key;
    }
}