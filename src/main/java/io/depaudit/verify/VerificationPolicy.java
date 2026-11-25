package io.depaudit.verify;

import io.depaudit.verify.pgp.KeySource;

import java.util.List;

/**
 * Reviewer-supplied policy: which repositories to ask, how much each answer is worth, and which
 * keys may vouch for a signature.
 *
 * <p>Separated from the metadata file on purpose. Nothing in a pull request can widen what the tool
 * considers authoritative; only this configuration can, and it lives in the review environment.
 *
 * @param keySource where public keys come from for signature checks. When it is {@link KeySource#none()},
 *                  signature verification is not attempted and the decision table falls back to
 *                  repository checksums alone. A signature is only ever <em>confirming</em> if the
 *                  signing key is in this source; a key fetched ad hoc proves nothing about identity.
 */
public record VerificationPolicy(
        List<RepositoryConfig> repositories,
        RepositoryClient client,
        boolean offline,
        KeySource keySource) {

    public VerificationPolicy {
        repositories = repositories == null ? List.of() : List.copyOf(repositories);
        keySource = keySource == null ? KeySource.NONE : keySource;
    }

    /** Policy without signature checking; repository checksums only. */
    public VerificationPolicy(List<RepositoryConfig> repositories, RepositoryClient client,
                              boolean offline) {
        this(repositories, client, offline, KeySource.none());
    }

    public static VerificationPolicy defaults() {
        return new VerificationPolicy(
                List.of(RepositoryConfig.mavenCentral()), new HttpRepositoryClient(), false,
                KeySource.none());
    }

    public static VerificationPolicy offlineWith(List<RepositoryConfig> repos, RepositoryClient c) {
        return new VerificationPolicy(repos, c, true, KeySource.none());
    }

    public boolean signaturesEnabled() {
        return keySource != KeySource.NONE;
    }

    public VerificationPolicy withKeySource(KeySource source) {
        return new VerificationPolicy(repositories, client, offline, source);
    }
}
