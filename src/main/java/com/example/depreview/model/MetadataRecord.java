package com.example.depreview.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public record MetadataRecord(
        Coordinates coordinates,
        String artifactName,
        Map<String, List<HashValue>> hashes,
        List<SourceRef> sources,
        List<SignerRef> signers,
        Integer line) {

    public MetadataRecord {
        if (coordinates == null) {
            throw new IllegalArgumentException("coordinates are required");
        }
        artifactName = artifactName == null ? "" : artifactName.trim();
        Map<String, List<HashValue>> copied = new LinkedHashMap<>();
        if (hashes != null) {
            hashes.forEach((key, value) -> copied.put(key, value == null ? List.of() : List.copyOf(value)));
        }
        hashes = Map.copyOf(copied);
        sources = sources == null ? List.of() : List.copyOf(sources);
        signers = signers == null ? List.of() : List.copyOf(signers);
    }

    public java.util.stream.Stream<HashValue> allHashes() {
        return hashes.values().stream().flatMap(List::stream);
    }

    public String versionSuffix() {
        String marker = "-" + coordinates.version();
        int index = artifactName.indexOf(marker);
        if (index < 0) {
            return "#" + artifactName;
        }
        return artifactName.substring(index + marker.length());
    }

    public String stableKey() {
        return coordinates.ga() + ":" + versionSuffix();
    }

    public String classifier() {
        String suffix = versionSuffix();
        if (suffix.startsWith("-")) {
            String rest = suffix.substring(1);
            int dot = rest.lastIndexOf('.');
            return dot > 0 ? rest.substring(0, dot) : rest;
        }
        return "";
    }

    public String extension() {
        String name = artifactName;
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        if (slash >= 0) {
            name = name.substring(slash + 1);
        }
        int dot = name.lastIndexOf('.');
        return dot >= 0 ? name.substring(dot + 1) : "";
    }
}
