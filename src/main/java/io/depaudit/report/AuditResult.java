package io.depaudit.report;

import io.depaudit.diff.MetadataChange;
import io.depaudit.diff.MetadataDiff;
import io.depaudit.diff.MetadataDiffer;
import io.depaudit.verify.TrustTier;
import io.depaudit.verify.UpgradeVerifier;
import io.depaudit.verify.Verdict;
import io.depaudit.verify.VerificationResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Everything the review needs, assembled but not yet rendered.
 *
 * <p>Built as an explicit result object rather than printing directly so the same audit can be
 * rendered for a human, serialised for CI, or asserted against in tests without re-running any
 * network work.
 */
public record AuditResult(
        String oldSource,
        String newSource,
        MetadataDiff diff,
        List<VerificationResult> changeVerdicts,
        List<UpgradeVerifier.UpgradeVerification> upgradeVerdicts,
        boolean offline) {

    public AuditResult {
        changeVerdicts = changeVerdicts == null ? List.of() : List.copyOf(changeVerdicts);
        upgradeVerdicts = upgradeVerdicts == null ? List.of() : List.copyOf(upgradeVerdicts);
    }

    /**
     * Should the merge be blocked?
     *
     * <p>Two independent routes to a block. A <em>contradiction</em> is a block regardless of how
     * the change was classified, because the outside world has said the value is wrong. A
     * <em>blocker-level change</em> is a block unless a canonical repository positively confirmed
     * it — trust-widening edits (a new unscoped key, an added {@code also-trust} value, verification
     * turned off) are not things any repository can vouch for, so an "unconfirmed" verdict on them
     * must not be read as permission to proceed.
     */
    public boolean isBlocking() {
        for (VerificationResult r : changeVerdicts) {
            if (r.isContradiction()) {
                return true;
            }
            if (r.change().isBlocker() && r.verdict() != Verdict.CONFIRMED_CANONICAL) {
                return true;
            }
        }
        for (UpgradeVerifier.UpgradeVerification u : upgradeVerdicts) {
            if (u.verdict() == Verdict.CONTRADICTED) {
                return true;
            }
        }
        return false;
    }

    public List<VerificationResult> contradictions() {
        return changeVerdicts.stream().filter(VerificationResult::isContradiction).toList();
    }

    public List<MetadataChange> blockers() {
        return diff.blockers();
    }

    public List<VerificationResult> unresolved() {
        return changeVerdicts.stream()
                .filter(r -> r.verdict() == Verdict.INCONCLUSIVE)
                .toList();
    }

    /**
     * Changes a human must decide on: everything neither confirmed strongly nor routine.
     *
     * <p>Blocker-level changes are deliberately excluded. They are already shown in the blocking
     * section, and repeating them here would make a single edit look like two problems — exactly
     * the noise this tool exists to remove. The renderer adds an "unconfirmed blocker" note where
     * that distinction matters.
     */
    public List<VerificationResult> needsHumanAttention() {
        List<VerificationResult> out = new ArrayList<>();
        for (VerificationResult r : changeVerdicts) {
            if (r.change().isBlocker() || r.isContradiction()) {
                continue;
            }
            if (r.change().severity() == MetadataChange.Severity.INFO) {
                continue;
            }
            Verdict v = r.verdict();
            if (v == Verdict.INCONCLUSIVE
                    || v == Verdict.CONFIRMED_MIRROR
                    || v == Verdict.INTERNAL_ONLY) {
                out.add(r);
            }
        }
        return out;
    }

    /** Upgrades whose new digests were confirmed by a canonical repository. */
    public long routineUpgrades() {
        return upgradeVerdicts.stream()
                .filter(u -> u.verdict() == Verdict.CONFIRMED_CANONICAL)
                .count();
    }

    public long upgradesNeedingAttention() {
        return upgradeVerdicts.stream()
                .filter(u -> u.verdict() != Verdict.CONFIRMED_CANONICAL
                        && u.verdict() != Verdict.CONFIRMED_MIRROR
                        && u.verdict() != Verdict.NOT_APPLICABLE)
                .count();
    }

    public TrustTier bestTier() {
        return upgradeVerdicts.stream()
                .map(UpgradeVerifier.UpgradeVerification::tier)
                .filter(java.util.Objects::nonNull)
                .max(java.util.Comparator.comparingInt(TrustTier::rank))
                .orElse(TrustTier.UNTRUSTED);
    }


    /** Direct access for renderers that want the raw upgrade list. */
    public List<MetadataDiffer.Upgrade> upgrades() {
        return diff.upgrades();
    }

    /**
     * Upgrade verdicts collapsed to one line per upgraded dependency.
     *
     * <p>An upgrade produces one verdict per artifact file (jar, pom, …), but a reviewer thinks in
     * terms of dependencies. Collapsing here keeps a 43-dependency bump from printing 86 lines.
     * The worst verdict across an upgrade's files wins: if the jar is confirmed but the pom
     * contradicts, the dependency must be shown as contradicted.
     */
    public List<UpgradeSummary> upgradeSummaries() {
        java.util.Map<String, List<UpgradeVerifier.UpgradeVerification>> byUpgrade =
                new java.util.LinkedHashMap<>();
        for (UpgradeVerifier.UpgradeVerification u : upgradeVerdicts) {
            byUpgrade.computeIfAbsent(u.upgrade().description(), k -> new ArrayList<>()).add(u);
        }
        List<UpgradeSummary> out = new ArrayList<>(byUpgrade.size());
        for (Map.Entry<String, List<UpgradeVerifier.UpgradeVerification>> e : byUpgrade.entrySet()) {
            List<UpgradeVerifier.UpgradeVerification> group = e.getValue();
            UpgradeVerifier.UpgradeVerification worst = group.stream()
                    .min(java.util.Comparator.comparingInt(
                            u -> verdictSeverity(u.verdict())))
                    .orElseThrow();
            out.add(new UpgradeSummary(e.getKey(), worst.verdict(), worst.tier(),
                    group.size(), worst.evidence(), worst.upgrade().newLine()));
        }
        return out;
    }

    /**
     * A whole dependency's upgrade outcome.
     *
     * @param description e.g. {@code org.apache.commons:commons-lang3 3.17.0 → 3.18.0}
     * @param verdict     the worst verdict among the upgrade's artifact files
     * @param tier        the best confirming tier, when one confirmed anything
     * @param fileCount   how many artifact files were checked
     * @param evidence    explanation for the worst verdict
     * @param newLine     line of the new component block
     */
    public record UpgradeSummary(String description, Verdict verdict, TrustTier tier,
                                 int fileCount, List<String> evidence, int newLine) {
        public UpgradeSummary {
            evidence = evidence == null ? List.of() : List.copyOf(evidence);
        }
    }

    private static int verdictSeverity(Verdict v) {
        return switch (v) {
            case CONTRADICTED -> 0;
            case INCONCLUSIVE -> 1;
            case INTERNAL_ONLY -> 2;
            case CONFIRMED_MIRROR -> 3;
            case CONFIRMED_BY_SIGNATURE -> 4;
            case CONFIRMED_CANONICAL -> 5;
            case NOT_APPLICABLE -> 6;
        };
    }
}
