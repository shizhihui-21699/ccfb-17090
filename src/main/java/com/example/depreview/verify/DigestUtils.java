package com.example.depreview.verify;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class DigestUtils {

    private DigestUtils() {
    }

    static String hex(Path file, String algorithm) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(javaName(algorithm));
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    static String javaName(String metadataAlgorithm) {
        return switch (metadataAlgorithm.toLowerCase()) {
            case "sha1" -> "SHA-1";
            case "sha256" -> "SHA-256";
            case "sha384" -> "SHA-384";
            case "sha512" -> "SHA-512";
            case "md5" -> "MD5";
            default -> metadataAlgorithm.toUpperCase().replace("SHA3-", "SHA3-");
        };
    }
}
