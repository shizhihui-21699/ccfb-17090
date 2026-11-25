package io.depaudit.verify.pgp;

import java.util.List;

/**
 * Outcome of verifying an artifact signature.
 *
 * @param valid          the signature verifies against the artifact bytes
 * @param signerKeyId    the signing key's primary key id, upper-cased hex, or {@code null}
 * @param signerUserId   the signer's user id when known
 * @param signerFingerprint full fingerprint when known
 * @param error          why verification did not succeed, when it did not
 * @param consultedSources where the public key came from
 */
public record SignatureVerification(
        boolean valid,
        String signerKeyId,
        String signerUserId,
        String signerFingerprint,
        String error,
        List<String> consultedSources) {

    public SignatureVerification {
        consultedSources = consultedSources == null ? List.of() : List.copyOf(consultedSources);
    }

    public static SignatureVerification failure(String reason, List<String> sources) {
        return new SignatureVerification(false, null, null, null, reason, sources);
    }
}
