package io.depaudit.model;

import java.util.List;

/**
 * A {@code <component group=... name=... version=...>} block.
 *
 * <p>Gradle emits components sorted by coordinates, which means an upgrade of one dependency
 * shows up as a deletion and an insertion at different places in the file rather than as a
 * modified block. Anything that diffs this file by position therefore drowns in false "changes".
 * The tool keys everything by coordinates instead.
 */
public record ComponentEntry(
        ArtifactRef coordinates,
        List<ArtifactEntry> artifacts,
        boolean regex,
        int line) {

    public ComponentEntry {
        artifacts = artifacts == null ? List.of() : List.copyOf(artifacts);
    }

    public String gav() {
        return coordinates.gav();
    }

    public ArtifactEntry artifact(String name) {
        for (ArtifactEntry a : artifacts) {
            if (a.name().equals(name)) {
                return a;
            }
        }
        return null;
    }
}
