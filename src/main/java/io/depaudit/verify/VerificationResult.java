package io.depaudit.verify;

import io.depaudit.diff.MetadataChange;
import io.depaudit.model.ArtifactRef;

import java.util.List;

/**
 * The result of verifying one {@link MetadataChange}.
 *
 * @param change    the change this verdict is about
 * @param verdict   what the outside world said about it
 * @param tier      the best trust tier that actively confirmed the value, or {@code null}
 * @param evidence  human-readable lines explaining the verdict, in the order they were established
 * @param resolvedCoords the coordinates actually consulted (may differ from the change's when a
 *                   component was renamed into a newer version)
 */
public record VerificationResult(
        MetadataChange change,
        Verdict verdict,
        TrustTier tier,
        List<String> evidence,
        ArtifactRef resolvedCoords) {

    public VerificationResult {
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
    }

    public boolean isContradiction() {
        return verdict == Verdict.CONTRADICTED;
    }

    public TrustTier effectiveTier() {
        return tier == null ? TrustTier.UNTRUSTED : tier;
    }
}
