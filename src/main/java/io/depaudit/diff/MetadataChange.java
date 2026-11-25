package io.depaudit.diff;

import io.depaudit.model.ArtifactRef;

import java.util.List;

/**
 * A single reviewable change found in a metadata file diff.
 *
 * <p>The point of this record is that every change is expressed in terms a reviewer can act on:
 * <em>which</em> dependency, <em>which</em> file inside it, <em>which</em> hash algorithm, <em>old</em>
 * value, <em>new</em> value, and <em>why it matters</em>. A raw line diff of the file gives none of
 * that.
 */
public record MetadataChange(
        ChangeKind kind,
        Category category,
        String subject,
        ArtifactRef coordinates,
        String artifactName,
        Detail detail,
        Severity severity,
        int oldLine,
        int newLine) {

    /** What part of the metadata file the change touches. */
    public enum Category {
        /** A {@code <component>} block as a whole (added / removed). */
        COMPONENT,
        /** A digest on one artifact file. */
        DIGEST,
        /** A PGP key id asserting a signature on one artifact file. */
        PGP_KEY,
        /** A {@code <trusted-key>} declaration in {@code <configuration>}. */
        TRUSTED_KEY,
        /** An {@code <ignored-key>} declaration. */
        IGNORED_KEY,
        /** {@code verify-metadata} / {@code verify-signatures} toggles. */
        VERIFICATION_TOGGLE,
        /** An element this tool does not model. Never silently ignored. */
        UNKNOWN_ELEMENT
    }

    public enum Severity {
        /** Routine churn from a legitimate version bump. */
        INFO,
        /** Needs a human to look, but has a plausible benign explanation. */
        REVIEW,
        /** Behaves like an attack: trust widened, or a value disagrees with an authority. */
        BLOCKER
    }

    /**
     * Typed payload so callers (and the report) never have to parse strings back apart.
     * Exactly one shape is populated depending on {@link Category}.
     */
    public sealed interface Detail {
        /** Coordinates appear or disappear wholesale. */
        record ComponentLifecycle(String note) implements Detail { }

        /** A hash value changed. */
        record DigestChange(
                String algorithm,
                String oldValue,
                String newValue,
                String oldOrigin,
                String newOrigin,
                boolean oldAlsoTrust,
                boolean newAlsoTrust) implements Detail { }

        /** A PGP key id set changed on an artifact. */
        record PgpKeysChange(List<String> added, List<String> removed) implements Detail { }

        /** A trusted-key declaration changed its key id or its scope. */
        record TrustedKeyChange(
                String oldId,
                String newId,
                String oldScope,
                String newScope,
                boolean keyMaterialAdded) implements Detail { }

        /** A toggle changed. */
        record ToggleChange(String name, boolean oldValue, boolean newValue) implements Detail { }

        /** Something we could not model, passed through verbatim. */
        record Unmodelled(String description) implements Detail { }
    }

    public boolean isBlocker() {
        return severity == Severity.BLOCKER;
    }
}
