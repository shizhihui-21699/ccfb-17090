package io.depaudit.verify;

/**
 * How much a repository's published checksum is worth as evidence.
 *
 * <p>The ordering matters and is the point. A tool that simply asks "does the new hash match
 * <em>any</em> repository we can reach?" can be defeated by adding a repository to the metadata's
 * own provenance and publishing the forged artifact there. Trust is therefore assigned by the
 * <em>reviewer's configuration</em>, never by anything written in the file under review, and a
 * change that only matches a repository of lower tier than the previous revision's match is
 * reported as a downgrade rather than a confirmation.
 */
public enum TrustTier {
    /**
     * The canonical public repository for the ecosystem (Maven Central). A checksum match here is
     * strong evidence that the bytes are the ones the library actually released.
     */
    CANONICAL(3),

    /**
     * A well-known mirror or redistributor (e.g. Google's Maven repo for Android artifacts, a
     * corporate-wide Nexus proxy). Useful, but its contents are downstream of somebody else.
     */
    MIRROR(2),

    /**
     * A repository internal to the organisation. Artifacts that only exist here cannot be checked
     * against the public ecosystem at all, so a match proves only that the value is consistent with
     * what the internal repository serves — not that it is the upstream project's build.
     */
    INTERNAL(1),

    /**
     * A third-party repository of unknown provenance. Recorded for completeness; never enough on
     * its own to confirm a change.
     */
    UNTRUSTED(0);

    private final int rank;

    TrustTier(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }

    public boolean atLeast(TrustTier other) {
        return rank >= other.rank;
    }
}
