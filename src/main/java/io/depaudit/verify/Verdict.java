package io.depaudit.verify;

/**
 * The outcome of trying to confirm one change against the outside world.
 *
 * <p>These are deliberately more granular than pass/fail. The hard cases this tool exists for are
 * exactly the ones where no clean pass/fail exists: an artifact that is only published to an
 * internal repository, or the same release legitimately built twice into different bytes. Lumping
 * those into "fail" would make the tool unusable on a real repository; lumping them into "pass"
 * would make it useless as a control.
 */
public enum Verdict {
    /** Matched a canonical public repository's published digest. Treat as the real release. */
    CONFIRMED_CANONICAL,

    /** Matched a trusted mirror but not the canonical repository. Plausible; a human should glance. */
    CONFIRMED_MIRROR,

    /** Matched nothing public, but the artifact plausibly lives only in the internal repository. */
    INTERNAL_ONLY,

    /**
     * The bytes are confirmed genuine (signature valid and signer trusted) even though no public
     * digest covered them — e.g. an internally rebuilt artifact signed by the upstream maintainer's
     * key, or a repository change that keeps the signature.
     */
    CONFIRMED_BY_SIGNATURE,

    /**
     * Contradicts an authority: the digest that the canonical repository publishes for this exact
     * version is different from the new value, or a signature by the expected maintainer fails to
     * verify. This is the attack signature.
     */
    CONTRADICTED,

    /** Could not be checked (offline, network failure, repository did not answer). */
    INCONCLUSIVE,

    /** Nothing to verify — e.g. an informational note, or a removal. */
    NOT_APPLICABLE
}
