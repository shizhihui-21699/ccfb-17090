package com.example.depreview.model;

import java.util.Comparator;

public record Coordinates(String groupId, String artifactId, String version)
        implements Comparable<Coordinates> {

    public Coordinates {
        if (groupId == null || groupId.isBlank()) {
            throw new IllegalArgumentException("groupId is required");
        }
        if (artifactId == null || artifactId.isBlank()) {
            throw new IllegalArgumentException("artifactId is required");
        }
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("version is required");
        }
    }

    public String ga() {
        return groupId + ":" + artifactId;
    }

    public String gav() {
        return ga() + ":" + version;
    }

    public String mavenPath() {
        return groupId.replace('.', '/') + '/' + artifactId + '/' + version;
    }

    @Override
    public int compareTo(Coordinates other) {
        return Comparator.comparing(Coordinates::gav).compare(this, other);
    }
}
