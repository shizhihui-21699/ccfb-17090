package com.example.depreview.model;

import java.util.List;

public record HashValue(
        String algorithm,
        String value,
        String origin,
        Integer line,
        List<String> alsoTrust) {

    public HashValue {
        algorithm = algorithm == null ? "" : algorithm.toLowerCase();
        value = value == null ? "" : value.trim().toLowerCase();
        origin = origin == null ? "" : origin;
        alsoTrust = alsoTrust == null ? List.of() : alsoTrust.stream()
                .map(v -> v == null ? "" : v.trim().toLowerCase())
                .filter(v -> !v.isBlank())
                .distinct()
                .toList();
    }

    public HashValue(String algorithm, String value, String origin, Integer line) {
        this(algorithm, value, origin, line, List.of());
    }

    public boolean strong() {
        return algorithm.equals("sha256") || algorithm.equals("sha384")
                || algorithm.equals("sha512") || algorithm.startsWith("sha3-");
    }

    public List<String> trustedValues() {
        if (alsoTrust.isEmpty()) {
            return List.of(value);
        }
        return java.util.stream.Stream.concat(java.util.stream.Stream.of(value), alsoTrust.stream())
                .distinct()
                .toList();
    }
}
