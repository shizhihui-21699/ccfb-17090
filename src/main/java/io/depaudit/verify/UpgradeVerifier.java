package io.depaudit.verify;

import io.depaudit.diff.MetadataDiffer;
import io.depaudit.model.ArtifactEntry;
import io.depaudit.model.ArtifactRef;
import io.depaudit.model.ComponentEntry;
import io.depaudit.model.VerificationMetadata;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Verifies correlated version upgrades.
 *
 * <p>This is the "normal change" path and the reason the tool can be used at all: a real dependency
 * bump touches hundreds of records, and every one of them must be checked — but checking them
 * produces one verdict per dependency, not one alarm per line. A bumped component is confirmed by
 * asking the same repositories about the <em>new</em> coordinates; because a released version's
 * digests are immutable, a bump whose new digests all match the canonical repository is
 * legitimately routine.
 *
 * <p>The interesting cases are the ones that <em>look</em> like a bump but are not: a bump whose new
 * version the canonical repository has never heard of, or whose digest for that version is
 * different. Both are reported as contradictions, because they are exactly what the attack in the
 * problem statement looks like — a plausible-looking version change carrying unrelated bytes.
 */
public final class UpgradeVerifier {

    private final VerificationPolicy policy;

    public UpgradeVerifier(VerificationPolicy policy) {
        this.policy = policy;
    }

    /**
     * Verifies one upgrade by checking each artifact file of the new component.
     *
     * @return one result per artifact file that carried a usable digest
     */
    public List<UpgradeVerification> verify(MetadataDiffer.Upgrade upgrade,
                                            VerificationMetadata newMetadata) {
        ComponentEntry target = newMetadata.componentsByGav().get(upgrade.to().gav());
        if (target == null) {
            return List.of(new UpgradeVerification(upgrade, Verdict.NOT_APPLICABLE, null,
                    List.of("new version not present in the file being reviewed"), List.of()));
        }
        List<UpgradeVerification> out = new ArrayList<>();
        for (ArtifactEntry artifact : target.artifacts()) {
            Optional<ArtifactEntry.Digest> digest = artifact.strongestDigest();
            if (digest.isEmpty()) {
                continue;
            }
            out.add(verifyArtifact(upgrade, target.coordinates(), artifact, digest.get()));
        }
        if (out.isEmpty()) {
            out.add(new UpgradeVerification(upgrade, Verdict.NOT_APPLICABLE, null,
                    List.of("new version records no digest"), List.of()));
        }
        return out;
    }

    private UpgradeVerification verifyArtifact(MetadataDiffer.Upgrade upgrade, ArtifactRef coords,
                                               ArtifactEntry artifact,
                                               ArtifactEntry.Digest digest) {
        if (policy.offline()) {
            return new UpgradeVerification(upgrade, Verdict.INCONCLUSIVE, null,
                    List.of("offline mode: no repositories consulted"), List.of());
        }

        List<String> evidence = new ArrayList<>();
        Map<String, String> perRepo = new LinkedHashMap<>();
        java.util.Set<String> unreachable = new java.util.LinkedHashSet<>();
        for (RepositoryConfig repo : policy.repositories()) {
            if (repo.offline()) {
                continue;
            }
            try {
                policy.client().publishedChecksum(repo, coords, artifact.name(), digest.algorithm())
                        .ifPresent(v -> perRepo.put(repo.id() + " (" + repo.tier().name().toLowerCase()
                                + ")", v));
            } catch (IOException e) {
                unreachable.add(repo.id());
                evidence.add(repo.id() + " could not be reached: " + e.getMessage());
            }
        }

        if (perRepo.isEmpty()) {
            evidence.add("no configured repository publishes " + coords.gav() + " " + artifact.name());
            // Absence of the version upstream is itself meaningful: a "bump" to a version the
            // canonical repository never published is a classic supply-chain injection. But that
            // conclusion only holds if we actually managed to ask. A repository that errored tells
            // us nothing, so an unreachable canonical repository downgrades this to INCONCLUSIVE
            // rather than manufacturing a contradiction out of a network failure.
            boolean canonicalReachable = policy.repositories().stream()
                    .filter(r -> r.tier() == TrustTier.CANONICAL && !r.offline())
                    .anyMatch(r -> !unreachable.contains(r.id()));
            if (canonicalReachable) {
                evidence.add("a canonical repository is configured, was reachable, and does not have "
                        + "this version");
                return new UpgradeVerification(upgrade, Verdict.CONTRADICTED, null, evidence,
                        List.copyOf(perRepo.values()));
            }
            if (!unreachable.isEmpty()) {
                evidence.add("could not confirm absence: " + unreachable.size()
                        + " repository/repositories unreachable");
            }
            return new UpgradeVerification(upgrade, Verdict.INCONCLUSIVE, null, evidence,
                    List.copyOf(perRepo.values()));
        }

        boolean anyAgrees = perRepo.values().stream()
                .anyMatch(v -> v.equalsIgnoreCase(digest.value()));
        Map.Entry<String, String> first = perRepo.entrySet().iterator().next();
        for (Map.Entry<String, String> e : perRepo.entrySet()) {
            evidence.add(e.getKey() + (e.getValue().equalsIgnoreCase(digest.value())
                    ? " publishes this value" : " publishes a DIFFERENT value"));
        }
        if (anyAgrees) {
            TrustTier tier = bestAgreeingTier(coords, artifact, digest);
            evidence.add("digest for the new version matches a repository at tier " + tier.name());
            Verdict verdict = switch (tier) {
                case CANONICAL -> Verdict.CONFIRMED_CANONICAL;
                case MIRROR -> Verdict.CONFIRMED_MIRROR;
                case INTERNAL -> Verdict.INTERNAL_ONLY;
                case UNTRUSTED -> Verdict.INCONCLUSIVE;
            };
            return new UpgradeVerification(upgrade, verdict, tier, evidence,
                    List.copyOf(perRepo.values()));
        }
        evidence.add("repository digests disagree with the value in the merge request");
        return new UpgradeVerification(upgrade, Verdict.CONTRADICTED, null, evidence,
                List.copyOf(perRepo.values()));
    }

    /** Highest tier among repositories that publish exactly this value. */
    private TrustTier bestAgreeingTier(ArtifactRef coords, ArtifactEntry artifact,
                                       ArtifactEntry.Digest digest) {
        TrustTier best = TrustTier.UNTRUSTED;
        for (RepositoryConfig repo : policy.repositories()) {
            if (repo.offline()) {
                continue;
            }
            try {
                Optional<String> v = policy.client()
                        .publishedChecksum(repo, coords, artifact.name(), digest.algorithm());
                if (v.isPresent() && v.get().equalsIgnoreCase(digest.value())
                        && repo.tier().rank() > best.rank()) {
                    best = repo.tier();
                }
            } catch (IOException ignored) {
                // Already surfaced in evidence; absence must not upgrade trust.
            }
        }
        return best;
    }

    /**
     * One upgrade's verification outcome.
     *
     * @param upgrade      which bump
     * @param verdict      what the repositories said
     * @param tier         best confirming tier, or {@code null}
     * @param evidence     explanation lines
     * @param observed     digests actually published by the repositories consulted
     */
    public record UpgradeVerification(MetadataDiffer.Upgrade upgrade, Verdict verdict,
                                      TrustTier tier, List<String> evidence,
                                      List<String> observed) {
        public UpgradeVerification {
            evidence = evidence == null ? List.of() : List.copyOf(evidence);
            observed = observed == null ? List.of() : List.copyOf(observed);
        }

        public String description() {
            return upgrade.description();
        }
    }
}
