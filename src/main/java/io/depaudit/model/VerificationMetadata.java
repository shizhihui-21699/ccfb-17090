package io.depaudit.model;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The parsed contents of a {@code gradle/verification-metadata.xml}.
 *
 * @param configuration   global toggles and key configuration
 * @param components      per-component digests, keyed by full coordinates
 * @param unknownElements everything the parser recognised the location of but did not model,
 *                        so that a diff can still warn about it instead of silently dropping it
 */
public record VerificationMetadata(
        Configuration configuration,
        List<ComponentEntry> components,
        List<String> unknownElements) {

    public VerificationMetadata {
        components = components == null ? List.of() : List.copyOf(components);
        unknownElements = unknownElements == null ? List.of() : List.copyOf(unknownElements);
    }

    /** Global {@code <configuration>} block. */
    public record Configuration(
            boolean verifyMetadata,
            boolean verifySignatures,
            List<TrustedKey> trustedKeys,
            List<String> ignoredKeys) {

        public Configuration {
            trustedKeys = trustedKeys == null ? List.of() : List.copyOf(trustedKeys);
            ignoredKeys = ignoredKeys == null ? List.of() : List.copyOf(ignoredKeys);
        }

        public static Configuration defaults() {
            return new Configuration(true, false, List.of(), List.of());
        }
    }

    /**
     * Index of components by their exact coordinates. Gradle writes coordinates sorted, but a
     * hand-edited file may not be, so lookups never rely on position.
     */
    public java.util.Map<String, ComponentEntry> componentsByGav() {
        java.util.Map<String, ComponentEntry> map = new java.util.LinkedHashMap<>();
        for (ComponentEntry c : components) {
            map.put(c.gav(), c);
        }
        return map;
    }

    public Set<String> groups() {
        Set<String> out = new LinkedHashSet<>();
        for (ComponentEntry c : components) {
            out.add(c.coordinates().group());
        }
        return out;
    }
}
