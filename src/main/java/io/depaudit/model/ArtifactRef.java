package io.depaudit.model;

import java.util.Objects;

/**
 * Fully-qualified coordinates of a dependency artifact: {@code group:name:version}.
 *
 * <p>{@code version} may be {@code null} for entries that act as a pattern or scope
 * (Gradle's {@code <trusted-key group="..." version="..."/>} style attributes, or
 * {@code regex="true"} entries). A {@code null} version means "any version".
 */
public record ArtifactRef(String group, String name, String version) {

    public ArtifactRef {
        Objects.requireNonNull(group, "group");
        Objects.requireNonNull(name, "name");
    }

    public static ArtifactRef parse(String gav) {
        String[] parts = gav.split(":", -1);
        if (parts.length < 2) {
            throw new IllegalArgumentException("Not coordinates: " + gav);
        }
        String version = parts.length > 2 && !parts[2].isBlank() ? parts[2] : null;
        return new ArtifactRef(parts[0], parts[1], version);
    }

    public String ga() {
        return group + ":" + name;
    }

    public String gav() {
        return version == null ? ga() : ga() + ":" + version;
    }

    /** Repository-relative path prefix, e.g. {@code org/apache/commons/commons-lang3/3.17.0}. */
    public String toPath() {
        return group.replace('.', '/') + "/" + name + "/" + (version == null ? "" : version);
    }

    public ArtifactRef withVersion(String newVersion) {
        return new ArtifactRef(group, name, newVersion);
    }

    @Override
    public String toString() {
        return gav();
    }
}
