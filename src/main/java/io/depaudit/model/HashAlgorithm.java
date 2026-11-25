package io.depaudit.model;

import java.util.Locale;
import java.util.Optional;

/** Hash algorithms that Gradle's verification metadata records. */
public enum HashAlgorithm {
    MD5("md5", 32),
    SHA1("sha1", 40),
    SHA256("sha256", 64),
    SHA512("sha512", 128);

    private final String xmlName;
    private final int hexLength;

    HashAlgorithm(String xmlName, int hexLength) {
        this.xmlName = xmlName;
        this.hexLength = hexLength;
    }

    public String xmlName() {
        return xmlName;
    }

    public int hexLength() {
        return hexLength;
    }

    public static Optional<HashAlgorithm> fromXmlName(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        for (HashAlgorithm a : values()) {
            if (a.xmlName.equals(n)) {
                return Optional.of(a);
            }
        }
        return Optional.empty();
    }

    /** Cheap plausibility check before we ever compare against a real file. */
    public boolean looksWellFormed(String hex) {
        return hex != null
                && hex.length() == hexLength
                && hex.chars().allMatch(c -> Character.digit(c, 16) >= 0);
    }

    /** Weaker algorithms never override a stronger one when deciding "the" digest. */
    public int strength() {
        return switch (this) {
            case MD5 -> 0;
            case SHA1 -> 1;
            case SHA256 -> 2;
            case SHA512 -> 3;
        };
    }
}
