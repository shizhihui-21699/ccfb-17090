package io.depaudit.verify;

import io.depaudit.diff.ChangeKind;
import io.depaudit.diff.MetadataChange;
import io.depaudit.diff.MetadataDiffer;
import io.depaudit.model.ArtifactRef;
import io.depaudit.model.HashAlgorithm;
import io.depaudit.verify.pgp.PgpSignatureVerifier;
import io.depaudit.verify.pgp.SignatureVerification;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Answers, for each digest change, the only question that actually matters to a reviewer:
 * <em>is the new value consistent with something authoritative?</em>
 *
 * <h2>The decision table</h2>
 *
 * <p>The hard cases in the problem statement are handled by asking, in order:
 *
 * <table>
 *   <caption>How a changed digest is judged</caption>
 *   <tr><th>Evidence found</th><th>Verdict</th></tr>
 *   <tr><td>Canonical repository publishes the new value for these coordinates</td>
 *       <td>{@code CONFIRMED_CANONICAL}</td></tr>
 *   <tr><td>Canonical repository publishes this version but a <em>different</em> digest</td>
 *       <td>{@code CONTRADICTED} — the attack signature. Decided first: a mirror agreeing cannot
 *           override it, because whoever forged the artifact also controls the mirror copy.</td></tr>
 *   <tr><td>Only a mirror publishes it</td><td>{@code CONFIRMED_MIRROR}</td></tr>
 *   <tr><td>No public repository has the coordinates at all, but an internal repository we were
 *           told about serves the new value</td><td>{@code INTERNAL_ONLY}</td></tr>
 *   <tr><td>New digest disagrees with the internal repository that served the old one</td>
 *       <td>{@code CONTRADICTED}</td></tr>
 *   <tr><td>Nothing could be reached</td><td>{@code INCONCLUSIVE}</td></tr>
 * </table>
 *
 * <p>Two rules keep "it matched <em>something</em>" from being treated as a pass. First, a
 * repository only counts for the coordinates that repository actually serves; we never accept a
 * digest from repository A for a file repository B published. Second, a confirmation from a
 * <em>lower</em> tier than the one that would have been available for the previous revision is
 * reported as {@code CONFIRMED_MIRROR} at best, never canonical.
 *
 * <p>The "same version, different bytes in different repositories" situation is legal — some
 * projects publish platform-specific or rebuilt artifacts to different repositories — so when we
 * find several repositories that each publish a digest for the same coordinates and they
 * <em>disagree with each other</em>, we say so explicitly instead of declaring the project's value
 * wrong. Canonical is the exception: a canonical disagreement is always a contradiction.
 */
public final class ArtifactVerifier {

    private final VerificationPolicy policy;

    public ArtifactVerifier(VerificationPolicy policy) {
        this.policy = policy;
    }

    public VerificationResult verify(MetadataChange change) {
        if (!(change.detail() instanceof MetadataChange.Detail.DigestChange dc)) {
            return new VerificationResult(change, Verdict.NOT_APPLICABLE, null, List.of(), null);
        }
        if (change.kind() == ChangeKind.REMOVED || dc.newValue() == null) {
            return new VerificationResult(change, Verdict.NOT_APPLICABLE, null,
                    List.of("value removed; nothing to confirm"), null);
        }
        return verifyDigest(change, dc);
    }

    private VerificationResult verifyDigest(MetadataChange change,
                                            MetadataChange.Detail.DigestChange dc) {
        ArtifactRef coords = change.coordinates();
        String fileName = change.artifactName();
        if (coords == null || coords.version() == null || fileName == null) {
            return new VerificationResult(change, Verdict.NOT_APPLICABLE, null,
                    List.of("change does not name a concrete artifact file"), null);
        }
        HashAlgorithm algorithm = HashAlgorithm.fromXmlName(dc.algorithm()).orElse(null);
        if (algorithm == null) {
            return new VerificationResult(change, Verdict.NOT_APPLICABLE, null,
                    List.of("not a hash algorithm: " + dc.algorithm()), coords);
        }
        if (policy.offline()) {
            return new VerificationResult(change, Verdict.INCONCLUSIVE, null,
                    List.of("offline mode: no repositories consulted"), coords);
        }

        List<String> evidence = new ArrayList<>();
        String wanted = dc.newValue();

        // Ask every configured repository that plausibly serves these coordinates.
        Map<RepositoryConfig, String> published = new java.util.LinkedHashMap<>();
        Map<RepositoryConfig, String> failures = new java.util.LinkedHashMap<>();
        for (RepositoryConfig repo : policy.repositories()) {
            if (repo.offline()) {
                continue;
            }
            try {
                Optional<String> got = policy.client()
                        .publishedChecksum(repo, coords, fileName, algorithm);
                if (got.isPresent()) {
                    published.put(repo, got.get());
                }
            } catch (IOException e) {
                failures.put(repo, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
            }
        }

        for (Map.Entry<RepositoryConfig, String> e : published.entrySet()) {
            String label = e.getKey().id() + " (" + e.getKey().tier().name().toLowerCase() + ")";
            if (e.getValue().equalsIgnoreCase(wanted)) {
                evidence.add(label + " publishes this value");
            } else {
                evidence.add(label + " publishes a DIFFERENT value " + shorten(e.getValue())
                        + " for " + coords.gav() + " " + fileName);
            }
        }
        for (Map.Entry<RepositoryConfig, String> e : failures.entrySet()) {
            evidence.add(e.getKey().id() + " could not be reached: " + e.getValue());
        }
        if (published.isEmpty() && failures.isEmpty()) {
            evidence.add("no configured repository has " + coords.gav() + " " + fileName);
        }

        // ---- Case 1: a canonical repository publishes this exact version.
        // This must be decided BEFORE any agreeing lower tier. If the canonical repository holds
        // the version and its bytes differ from the merge request's value, nothing else can make
        // the value acceptable: a mirror that also serves the forged bytes is downstream of the
        // person who forged them, not independent evidence.
        Optional<Map.Entry<RepositoryConfig, String>> canonical = published.entrySet()
                .stream()
                .filter(e -> e.getKey().tier() == TrustTier.CANONICAL)
                .findFirst();
        if (canonical.isPresent()) {
            if (canonical.get().getValue().equalsIgnoreCase(wanted)) {
                TrustTier tier = canonical.get().getKey().tier();
                evidence.add("canonical repository publishes this value");
                return new VerificationResult(change, Verdict.CONFIRMED_CANONICAL, tier,
                        evidence, coords);
            }
            evidence.add("the canonical repository's digest for this exact version differs from the "
                    + "value in the merge request");
            return new VerificationResult(change, Verdict.CONTRADICTED,
                    canonical.get().getKey().tier(), evidence, coords);
        }

        // ---- Case 2: at least one non-canonical repository agrees with the new value.
        Optional<RepositoryConfig> bestAgreeing = published.entrySet().stream()
                .filter(e -> e.getValue().equalsIgnoreCase(wanted))
                .map(Map.Entry::getKey)
                .max(java.util.Comparator.comparingInt(r -> r.tier().rank()));

        if (bestAgreeing.isPresent()) {
            RepositoryConfig repo = bestAgreeing.get();
            TrustTier tier = repo.tier();
            evidence.add("best confirming repository: " + repo.id() + " at tier " + tier.name());
            Verdict verdict = switch (tier) {
                case CANONICAL -> Verdict.CONFIRMED_CANONICAL; // unreachable, handled above
                case MIRROR -> Verdict.CONFIRMED_MIRROR;
                case INTERNAL -> Verdict.INTERNAL_ONLY;
                case UNTRUSTED -> Verdict.INCONCLUSIVE;
            };
            return new VerificationResult(change, verdict, tier, evidence, coords);
        }

        // ---- Case 3: an internal repository serves these coordinates but with a different digest.
        // If the old revision's value matched that repository and the new one does not, the change
        // swaps out the artifact the organisation would actually download.
        Optional<Map.Entry<RepositoryConfig, String>> internalDisagrees = published.entrySet()
                .stream()
                .filter(e -> e.getKey().tier() == TrustTier.INTERNAL)
                .findFirst();
        if (internalDisagrees.isPresent()) {
            boolean oldMatchedInternal = dc.oldValue() != null
                    && dc.oldValue().equalsIgnoreCase(internalDisagrees.get().getValue());
            evidence.add("internal repository publishes a different digest for these coordinates");
            if (oldMatchedInternal) {
                evidence.add("the previous value matched that repository; this change does not");
                return new VerificationResult(change, Verdict.CONTRADICTED,
                        internalDisagrees.get().getKey().tier(), evidence, coords);
            }
            // No digest agreement, but the bytes may still be provably genuine via a signature.
            Optional<VerificationResult> bySignature =
                    signatureConfirm(change, dc, coords, fileName, evidence);
            if (bySignature.isPresent()) {
                return bySignature.get();
            }
            return new VerificationResult(change, Verdict.INCONCLUSIVE,
                    internalDisagrees.get().getKey().tier(), evidence, coords);
        }

        // ---- Case 4: a mirror or untrusted repository serves it with a different value.
        Optional<Map.Entry<RepositoryConfig, String>> anyDisagrees = published.entrySet().stream()
                .findFirst();
        if (anyDisagrees.isPresent()) {
            evidence.add("only lower-tier repositories have these coordinates, and none agrees");
            Optional<VerificationResult> bySignature =
                    signatureConfirm(change, dc, coords, fileName, evidence);
            if (bySignature.isPresent()) {
                return bySignature.get();
            }
            return new VerificationResult(change, Verdict.INCONCLUSIVE,
                    anyDisagrees.get().getKey().tier(), evidence, coords);
        }

        // ---- Case 5: nothing published these coordinates at all. A signature is the only remaining
        // way to establish that the bytes are the maintainer's, and it is a strong one: it does not
        // depend on which repository served the file.
        Optional<VerificationResult> bySignature =
                signatureConfirm(change, dc, coords, fileName, evidence);
        if (bySignature.isPresent()) {
            return bySignature.get();
        }

        return new VerificationResult(change, Verdict.INCONCLUSIVE,
                failures.isEmpty() ? null : TrustTier.UNTRUSTED, evidence, coords);
    }

    /**
     * Tries to confirm the changed value by verifying the artifact's detached signature against a
     * trusted key.
     *
     * <p><b>The signature must vouch for the value actually in the merge request, not merely for
     * the bytes the repository happens to serve.</b> A valid signature over the downloaded jar
     * says "this jar is the maintainer's"; it says nothing about whether the hash recorded in the
     * metadata matches that jar. Confirming on the former alone would let an attacker sign nothing
     * and simply write a wrong hash — the metadata would still fail to verify at build time, or
     * worse, point at a different artifact entirely. So this method first recomputes the digest of
     * the signed bytes and requires it to equal the value under review before it will confirm.
     *
     * <p>Returns empty when signatures are disabled, when the repository publishes no {@code .asc},
     * or when the signature does not verify — the caller then falls through to its own verdict
     * rather than treating a missing signature as a contradiction (most of Maven is unsigned, and a
     * tool that blocked on that would be switched off).
     */
    private Optional<VerificationResult> signatureConfirm(MetadataChange change,
                                                          MetadataChange.Detail.DigestChange dc,
                                                          ArtifactRef coords, String fileName,
                                                          List<String> evidence) {
        if (!policy.signaturesEnabled() || fileName == null) {
            return Optional.empty();
        }
        HashAlgorithm algorithm = HashAlgorithm.fromXmlName(dc.algorithm()).orElse(null);
        if (algorithm == null || dc.newValue() == null) {
            return Optional.empty();
        }
        String wanted = dc.newValue();

        // Ask each configured repository in tier order: the signature belongs to whichever
        // repository actually serves the artifact, and we want the most trustworthy one.
        List<RepositoryConfig> ordered = policy.repositories().stream()
                .filter(r -> !r.offline())
                .sorted(java.util.Comparator.comparingInt(
                        (RepositoryConfig r) -> -r.tier().rank()))
                .toList();
        for (RepositoryConfig repo : ordered) {
            try {
                Optional<byte[]> asc = policy.client().signature(repo, coords, fileName);
                if (asc.isEmpty()) {
                    continue;
                }
                Optional<InputStream> in = policy.client().openArtifact(repo, coords, fileName);
                if (in.isEmpty()) {
                    continue;
                }
                byte[] bytes;
                try (InputStream stream = in.get()) {
                    bytes = stream.readAllBytes();
                }

                // The join: the signed bytes must BE the artifact whose hash is being reviewed.
                String actual = digestOf(bytes, algorithm);
                if (actual == null || !actual.equalsIgnoreCase(wanted)) {
                    evidence.add("the artifact " + repo.id() + " serves does not match the " + dc.algorithm()
                            + " value in the merge request (served bytes hash to "
                            + shorten(actual) + ")");
                    continue;
                }

                SignatureVerification sig = new PgpSignatureVerifier()
                        .verify(asc.get(), bytes, policy.keySource());
                if (sig.valid()) {
                    evidence.add("signature by " + describeSigner(sig) + " verifies against the "
                            + "artifact from " + repo.id() + ", and that artifact hashes to the "
                            + "value under review");
                    return Optional.of(new VerificationResult(change,
                            Verdict.CONFIRMED_BY_SIGNATURE, repo.tier(), evidence, coords));
                }
                if (sig.error() != null) {
                    evidence.add("signature from " + repo.id() + " did not verify: " + sig.error());
                }
            } catch (IOException e) {
                evidence.add("could not fetch signature/artifact from " + repo.id() + ": "
                        + e.getMessage());
            }
        }
        return Optional.empty();
    }

    /** Digest of in-memory bytes, or {@code null} if the algorithm is unavailable. */
    private static String digestOf(byte[] bytes, HashAlgorithm algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(jcaName(algorithm));
            return HexFormat.of().formatHex(md.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private static String describeSigner(SignatureVerification sig) {
        String uid = sig.signerUserId() == null ? "<unknown user id>" : sig.signerUserId();
        String fp = sig.signerFingerprint() == null ? sig.signerKeyId() : sig.signerFingerprint();
        return uid + " (" + fp + ")";
    }

    /**
     * Recomputes a digest by downloading the artifact, for the case where a repository publishes no
     * sidecar checksum (some do not) but still serves the bytes. Expensive and network-heavy, so
     * callers use it as a fallback rather than the default path.
     */
    public Optional<String> computeDigest(RepositoryConfig repo, ArtifactRef coords,
                                          String fileName, HashAlgorithm algorithm)
            throws IOException {
        Optional<InputStream> in = policy.client().openArtifact(repo, coords, fileName);
        if (in.isEmpty()) {
            return Optional.empty();
        }
        try (InputStream stream = in.get()) {
            MessageDigest md = MessageDigest.getInstance(jcaName(algorithm));
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = stream.read(buf)) >= 0) {
                md.update(buf, 0, n);
            }
            return Optional.of(HexFormat.of().formatHex(md.digest()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM lacks " + algorithm, e);
        }
    }

    public static String jcaName(HashAlgorithm a) {
        return switch (a) {
            case MD5 -> "MD5";
            case SHA1 -> "SHA-1";
            case SHA256 -> "SHA-256";
            case SHA512 -> "SHA-512";
        };
    }

    private static String shorten(String hex) {
        return hex == null || hex.length() <= 12 ? String.valueOf(hex) : hex.substring(0, 12) + "…";
    }

    /** Convenience for verifying a whole diff. Order is preserved (already severity-sorted). */
    public List<VerificationResult> verifyAll(List<MetadataChange> changes) {
        List<VerificationResult> out = new ArrayList<>(changes.size());
        for (MetadataChange c : changes) {
            out.add(verify(c));
        }
        return out;
    }

    /** True when a change names an upgrade target we should verify rather than its old coordinates. */
    public static Optional<ArtifactRef> upgradeTarget(MetadataDiffer.Upgrade u) {
        return Optional.ofNullable(u.to());
    }
}
