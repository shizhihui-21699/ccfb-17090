package io.depaudit;

import io.depaudit.diff.MetadataDiff;
import io.depaudit.diff.MetadataDiffer;
import io.depaudit.model.VerificationMetadata;
import io.depaudit.parse.MetadataParseException;
import io.depaudit.parse.VerificationMetadataParser;
import io.depaudit.report.AuditResult;
import io.depaudit.verify.ArtifactVerifier;
import io.depaudit.verify.UpgradeVerifier;
import io.depaudit.verify.VerificationPolicy;
import io.depaudit.verify.VerificationResult;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Ties the three stages together: parse both revisions, diff them, then verify.
 *
 * <p>Kept separate from the CLI so the same pipeline can be driven from a CI plugin, a
 * pull-request bot, or a test without argument parsing in the way.
 */
public final class AuditService {

    private final VerificationMetadataParser parser = new VerificationMetadataParser();

    /**
     * Audits a change from {@code oldFile} to {@code newFile}.
     *
     * @param oldFile previous revision; may be {@code null} to audit a file with no history (every
     *                entry is then "added", which is noisy but safe)
     * @param newFile revision under review
     */
    public AuditResult audit(Path oldFile, Path newFile, VerificationPolicy policy)
            throws MetadataParseException {
        VerificationMetadata oldMd = oldFile == null
                ? new VerificationMetadata(VerificationMetadata.Configuration.defaults(),
                        List.of(), List.of())
                : parser.parse(oldFile);
        VerificationMetadata newMd = parser.parse(newFile);

        MetadataDiff diff = new MetadataDiffer().diff(oldMd, newMd);

        // Verification runs in both modes; the policy itself short-circuits every network call when
        // offline, so a single path keeps the two behaviours from drifting apart as the decision
        // table grows.
        List<VerificationResult> verdicts =
                new ArtifactVerifier(policy).verifyAll(diff.changes());

        List<UpgradeVerifier.UpgradeVerification> upgradeVerdicts = new ArrayList<>();
        UpgradeVerifier uv = new UpgradeVerifier(policy);
        for (MetadataDiffer.Upgrade upgrade : diff.upgrades()) {
            upgradeVerdicts.addAll(uv.verify(upgrade, newMd));
        }

        return new AuditResult(
                oldFile == null ? "<none>" : oldFile.toString(),
                newFile.toString(),
                diff,
                verdicts,
                upgradeVerdicts,
                policy.offline());
    }
}
