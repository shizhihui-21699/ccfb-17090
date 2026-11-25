package io.depaudit.diff;

import io.depaudit.model.ArtifactEntry;
import io.depaudit.model.ArtifactRef;
import io.depaudit.model.ComponentEntry;
import io.depaudit.model.HashAlgorithm;
import io.depaudit.model.TrustedKey;
import io.depaudit.model.VerificationMetadata;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Computes the security-relevant delta between two revisions of a metadata file.
 *
 * <p>The central difficulty this class exists to solve: a perfectly ordinary version bump rewrites
 * <em>hundreds</em> of unrelated lines. Gradle writes components sorted by coordinates, so bumping
 * {@code foo} from 1.0 to 1.1 deletes a block near the top of the file and inserts one near the
 * bottom — a naive positional diff reports two giant changes and buries the one line an attacker
 * actually changed. This differ therefore keys everything by <em>coordinates</em>
 * ({@code group:name:version}) and by artifact name, so that:
 *
 * <ul>
 *   <li>a version bump is recognised as one correlated {@link Upgrade} rather than hundreds of
 *       unrelated add/remove events;</li>
 *   <li>a digest that changes <em>without</em> the version changing stands out as the anomaly it
 *       is;</li>
 *   <li>adding an {@code <also-trust>} value — which silently widens what a build accepts without
 *       touching the primary hash — is reported at all, since most reviewers never see it.</li>
 * </ul>
 *
 * <p>This stage is deliberately <em>not</em> the place that decides whether a new hash is correct.
 * It classifies what changed and how suspicious the shape of the change is. Confirming values
 * against repositories and signatures is the verifier's job.
 */
public final class MetadataDiffer {

    public MetadataDiff diff(VerificationMetadata oldMd, VerificationMetadata newMd) {
        List<MetadataChange> changes = new ArrayList<>();
        List<Upgrade> upgrades = new ArrayList<>();

        Map<String, ComponentEntry> oldByGav = oldMd.componentsByGav();
        Map<String, ComponentEntry> newByGav = newMd.componentsByGav();

        // ---- 1. Correlate removed/added components into version upgrades -------------------
        // Group by GA. If a GA lost version(s) and gained version(s) it is an upgrade, not an
        // unrelated deletion plus insertion.
        Map<String, List<ComponentEntry>> removedByGa = groupByGa(oldByGav, newByGav, true);
        Map<String, List<ComponentEntry>> addedByGa = groupByGa(oldByGav, newByGav, false);

        Set<String> handledRemoved = new LinkedHashSet<>();
        Set<String> handledAdded = new LinkedHashSet<>();

        TreeSet<String> allGa = new TreeSet<>();
        allGa.addAll(removedByGa.keySet());
        allGa.addAll(addedByGa.keySet());

        for (String ga : allGa) {
            List<ComponentEntry> removed = removedByGa.getOrDefault(ga, List.of());
            List<ComponentEntry> added = addedByGa.getOrDefault(ga, List.of());
            if (!removed.isEmpty() && !added.isEmpty()) {
                for (ComponentEntry r : removed) {
                    for (ComponentEntry a : added) {
                        upgrades.add(new Upgrade(
                                r.coordinates(), a.coordinates(), r.line(), a.line()));
                    }
                }
                removed.forEach(c -> handledRemoved.add(c.gav()));
                added.forEach(c -> handledAdded.add(c.gav()));
            }
        }

        // ---- 2. Components present on both sides: compare contents -------------------------
        TreeSet<String> bothSides = new TreeSet<>(oldByGav.keySet());
        bothSides.retainAll(newByGav.keySet());
        for (String gav : bothSides) {
            ComponentEntry o = oldByGav.get(gav);
            ComponentEntry n = newByGav.get(gav);
            if (o.regex() != n.regex()) {
                changes.add(new MetadataChange(
                        ChangeKind.MODIFIED, MetadataChange.Category.COMPONENT,
                        gav, o.coordinates(), null,
                        new MetadataChange.Detail.ComponentLifecycle(
                                "regex attribute changed from " + o.regex() + " to " + n.regex()),
                        MetadataChange.Severity.REVIEW, o.line(), n.line()));
            }
            diffArtifacts(o, n, changes);
        }
        // ---- 3. Genuinely added / removed components ---------------------------------------
        // A removal with no matching addition is unusual: dependencies are normally added, and a
        // removal usually accompanies an upgrade. Flag for review rather than assume benign.
        for (ComponentEntry r : oldMd.components()) {
            if (!handledRemoved.contains(r.gav()) && !newByGav.containsKey(r.gav())) {
                changes.add(new MetadataChange(
                        ChangeKind.REMOVED, MetadataChange.Category.COMPONENT,
                        r.gav(), r.coordinates(), null,
                        new MetadataChange.Detail.ComponentLifecycle(
                                "component removed; no replacement version of "
                                        + r.coordinates().ga() + " was added"),
                        MetadataChange.Severity.REVIEW, r.line(), 0));
            }
        }
        for (ComponentEntry a : newMd.components()) {
            if (!handledAdded.contains(a.gav()) && !oldByGav.containsKey(a.gav())) {
                changes.add(new MetadataChange(
                        ChangeKind.ADDED, MetadataChange.Category.COMPONENT,
                        a.gav(), a.coordinates(), null,
                        new MetadataChange.Detail.ComponentLifecycle(
                                "new component (no earlier version of " + a.coordinates().ga()
                                        + " in the file)"),
                        MetadataChange.Severity.INFO, 0, a.line()));
            }
        }

        // ---- 4. Configuration-level changes ------------------------------------------------
        diffConfiguration(oldMd.configuration(), newMd.configuration(), changes);

        // ---- 5. Anything the parser did not model ------------------------------------------
        // Reported so a hand-injected element cannot hide by being unrecognised.
        Set<String> newUnknown = new LinkedHashSet<>(newMd.unknownElements());
        newUnknown.removeAll(oldMd.unknownElements());
        for (String u : newUnknown) {
            changes.add(new MetadataChange(
                    ChangeKind.ADDED, MetadataChange.Category.UNKNOWN_ELEMENT,
                    u, null, null,
                    new MetadataChange.Detail.Unmodelled(u),
                    MetadataChange.Severity.REVIEW, 0, 0));
        }
        for (String u : oldMd.unknownElements()) {
            if (!newMd.unknownElements().contains(u)) {
                changes.add(new MetadataChange(
                        ChangeKind.REMOVED, MetadataChange.Category.UNKNOWN_ELEMENT,
                        u, null, null,
                        new MetadataChange.Detail.Unmodelled(u),
                        MetadataChange.Severity.INFO, 0, 0));
            }
        }

        changes.sort(Comparator
                .comparingInt((MetadataChange c) -> severityRank(c.severity()))
                .thenComparing(c -> c.category().ordinal())
                .thenComparing(MetadataChange::subject));

        return new MetadataDiff(List.copyOf(changes), List.copyOf(upgrades));
    }

    // ------------------------------------------------------------------ artifacts

    private void diffArtifacts(ComponentEntry oldC, ComponentEntry newC,
                               List<MetadataChange> out) {
        Map<String, ArtifactEntry> oldArts = byName(oldC.artifacts());
        Map<String, ArtifactEntry> newArts = byName(newC.artifacts());

        TreeSet<String> names = new TreeSet<>(oldArts.keySet());
        names.addAll(newArts.keySet());

        for (String name : names) {
            ArtifactEntry o = oldArts.get(name);
            ArtifactEntry n = newArts.get(name);
            if (o == null) {
                // An artifact file newly covered by verification.
                out.add(new MetadataChange(
                        ChangeKind.ADDED, MetadataChange.Category.DIGEST,
                        oldC.gav() + " " + name, oldC.coordinates(), name,
                        new MetadataChange.Detail.ComponentLifecycle(
                                "artifact newly added to an existing component entry"),
                        MetadataChange.Severity.REVIEW, 0, n.line()));
                continue;
            }
            if (n == null) {
                out.add(new MetadataChange(
                        ChangeKind.REMOVED, MetadataChange.Category.DIGEST,
                        oldC.gav() + " " + name, oldC.coordinates(), name,
                        new MetadataChange.Detail.ComponentLifecycle(
                                "artifact no longer verified for this component"),
                        MetadataChange.Severity.REVIEW, o.line(), 0));
                continue;
            }
            diffDigests(oldC, o, n, out);
            diffPgp(oldC, o, n, out);
        }
    }

    /**
     * Compares the recorded digests of one artifact file.
     *
     * <p>This method only ever runs for a component whose {@code group:name:version} is
     * <em>identical</em> on both sides, and a released artifact's bytes are immutable. So a primary
     * digest that changes here has no legitimate explanation: it is not upgrade churn, it is either
     * a corrupted entry or an attempt to make a different artifact verify. It is therefore raised to
     * {@link MetadataChange.Severity#REVIEW} at minimum, and the verifier is expected to confirm it
     * against the repository. (Digest changes that <em>do</em> accompany a version bump are handled
     * separately: they live on different coordinates and are checked per-upgrade by the verifier.)
     *
     * <p>Three distinct events are reported separately because they mean different things:
     * a primary value changing, an {@code also-trust} value appearing (silently widening
     * acceptance without touching the primary hash), and the algorithm set changing (e.g. dropping
     * sha256 in favour of sha1 is a downgrade even when no individual value looks tampered with).
     */
    private void diffDigests(ComponentEntry component, ArtifactEntry o, ArtifactEntry n,
                             List<MetadataChange> out) {
        for (HashAlgorithm alg : HashAlgorithm.values()) {
            List<ArtifactEntry.Digest> olds = o.digestsOf(alg);
            List<ArtifactEntry.Digest> news = n.digestsOf(alg);
            if (olds.isEmpty() && news.isEmpty()) {
                continue;
            }

            ArtifactEntry.Digest primaryOld = primary(olds);
            ArtifactEntry.Digest primaryNew = primary(news);

            if (primaryOld != null && primaryNew != null
                    && !Objects.equals(primaryOld.value(), primaryNew.value())) {
                out.add(new MetadataChange(
                        ChangeKind.MODIFIED, MetadataChange.Category.DIGEST,
                        component.gav() + " " + o.name() + " " + alg.xmlName(),
                        component.coordinates(), o.name(),
                        new MetadataChange.Detail.DigestChange(
                                alg.xmlName(), primaryOld.value(), primaryNew.value(),
                                primaryOld.origin(), primaryNew.origin(),
                                primaryOld.alsoTrust(), primaryNew.alsoTrust()),
                        MetadataChange.Severity.REVIEW,
                        primaryOld.line(), primaryNew.line()));
            } else if (primaryOld == null && primaryNew != null) {
                // Algorithm added where it previously was not recorded: usually benign, but
                // adding md5/sha1 where a stronger one already existed is a downgrade enabler.
                out.add(new MetadataChange(
                        ChangeKind.ADDED, MetadataChange.Category.DIGEST,
                        component.gav() + " " + o.name() + " " + alg.xmlName(),
                        component.coordinates(), o.name(),
                        new MetadataChange.Detail.DigestChange(
                                alg.xmlName(), null, primaryNew.value(),
                                null, primaryNew.origin(), false, false),
                        alg.strength() < HashAlgorithm.SHA256.strength()
                                ? MetadataChange.Severity.REVIEW
                                : MetadataChange.Severity.INFO,
                        0, primaryNew.line()));
            } else if (primaryOld != null && primaryNew == null) {
                boolean strongerRemoved = alg.strength() >= HashAlgorithm.SHA256.strength();
                out.add(new MetadataChange(
                        ChangeKind.REMOVED, MetadataChange.Category.DIGEST,
                        component.gav() + " " + o.name() + " " + alg.xmlName(),
                        component.coordinates(), o.name(),
                        new MetadataChange.Detail.DigestChange(
                                alg.xmlName(), primaryOld.value(), null,
                                primaryOld.origin(), null, false, false),
                        strongerRemoved ? MetadataChange.Severity.REVIEW
                                : MetadataChange.Severity.INFO,
                        primaryOld.line(), 0));
            }

            // also-trust values: set difference. An addition accepts an extra artifact that the
            // primary hash does not cover, which is exactly the shape of a targeted bypass.
            Set<String> oldAlso = alsoTrustValues(olds);
            Set<String> newAlso = alsoTrustValues(news);
            for (String added : minus(newAlso, oldAlso)) {
                out.add(new MetadataChange(
                        ChangeKind.ADDED, MetadataChange.Category.DIGEST,
                        component.gav() + " " + o.name() + " " + alg.xmlName() + " (also-trust)",
                        component.coordinates(), o.name(),
                        new MetadataChange.Detail.DigestChange(
                                alg.xmlName(), null, added, null, null, false, true),
                        MetadataChange.Severity.BLOCKER, 0, lineOf(news, alg, added)));
            }
            for (String removed : minus(oldAlso, newAlso)) {
                out.add(new MetadataChange(
                        ChangeKind.REMOVED, MetadataChange.Category.DIGEST,
                        component.gav() + " " + o.name() + " " + alg.xmlName() + " (also-trust)",
                        component.coordinates(), o.name(),
                        new MetadataChange.Detail.DigestChange(
                                alg.xmlName(), removed, null, null, null, true, false),
                        MetadataChange.Severity.INFO,
                        lineOf(olds, alg, removed), 0));
            }
        }

        // The origin attribute is prose in Gradle's own output ("Generated by Gradle"). If it
        // starts looking like a URL or host, that is a fabricated provenance claim.
        ArtifactEntry.Digest po = o.strongestDigest().orElse(null);
        ArtifactEntry.Digest pn = n.strongestDigest().orElse(null);
        if (po != null && pn != null
                && !Objects.equals(nullToEmpty(po.origin()), nullToEmpty(pn.origin()))) {
            boolean suspiciousNew = looksLikeLocation(pn.origin());
            out.add(new MetadataChange(
                    ChangeKind.MODIFIED, MetadataChange.Category.DIGEST,
                    component.gav() + " " + o.name() + " origin",
                    component.coordinates(), o.name(),
                    new MetadataChange.Detail.DigestChange(
                            "origin", po.origin(), pn.origin(), po.origin(), pn.origin(),
                            false, false),
                    suspiciousNew ? MetadataChange.Severity.BLOCKER : MetadataChange.Severity.REVIEW,
                    po.line(), pn.line()));
        }
    }

    private void diffPgp(ComponentEntry component, ArtifactEntry o, ArtifactEntry n,
                         List<MetadataChange> out) {
        Set<String> oldKeys = new LinkedHashSet<>(o.pgpKeys());
        Set<String> newKeys = new LinkedHashSet<>(n.pgpKeys());
        if (oldKeys.equals(newKeys)) {
            return;
        }
        List<String> added = minus(newKeys, oldKeys);
        List<String> removed = minus(oldKeys, newKeys);
        out.add(new MetadataChange(
                ChangeKind.MODIFIED, MetadataChange.Category.PGP_KEY,
                component.gav() + " " + o.name() + " pgp",
                component.coordinates(), o.name(),
                new MetadataChange.Detail.PgpKeysChange(added, removed),
                // Swapping which key may sign an artifact is a trust change, not churn.
                MetadataChange.Severity.REVIEW, o.line(), n.line()));
    }

    // ------------------------------------------------------------------ configuration

    private void diffConfiguration(VerificationMetadata.Configuration o,
                                   VerificationMetadata.Configuration n,
                                   List<MetadataChange> out) {
        if (o.verifyMetadata() != n.verifyMetadata()) {
            out.add(new MetadataChange(
                    ChangeKind.MODIFIED, MetadataChange.Category.VERIFICATION_TOGGLE,
                    "verify-metadata", null, null,
                    new MetadataChange.Detail.ToggleChange(
                            "verify-metadata", o.verifyMetadata(), n.verifyMetadata()),
                    n.verifyMetadata() ? MetadataChange.Severity.INFO
                            : MetadataChange.Severity.BLOCKER,
                    0, 0));
        }
        if (o.verifySignatures() != n.verifySignatures()) {
            out.add(new MetadataChange(
                    ChangeKind.MODIFIED, MetadataChange.Category.VERIFICATION_TOGGLE,
                    "verify-signatures", null, null,
                    new MetadataChange.Detail.ToggleChange(
                            "verify-signatures", o.verifySignatures(), n.verifySignatures()),
                    n.verifySignatures() ? MetadataChange.Severity.INFO
                            : MetadataChange.Severity.REVIEW,
                    0, 0));
        }

        diffTrustedKeys(o.trustedKeys(), n.trustedKeys(), out);

        Set<String> oIgnored = new LinkedHashSet<>(o.ignoredKeys());
        Set<String> nIgnored = new LinkedHashSet<>(n.ignoredKeys());
        for (String added : minus(nIgnored, oIgnored)) {
            out.add(new MetadataChange(
                    ChangeKind.ADDED, MetadataChange.Category.IGNORED_KEY,
                    "ignored-key " + added, null, null,
                    new MetadataChange.Detail.Unmodelled(
                            "key " + added + " is now exempt from signature verification"),
                    MetadataChange.Severity.REVIEW, 0, 0));
        }
        for (String removed : minus(oIgnored, nIgnored)) {
            out.add(new MetadataChange(
                    ChangeKind.REMOVED, MetadataChange.Category.IGNORED_KEY,
                    "ignored-key " + removed, null, null,
                    new MetadataChange.Detail.Unmodelled(
                            "key " + removed + " is no longer exempt from verification"),
                    MetadataChange.Severity.INFO, 0, 0));
        }
    }

    /**
     * Trusted keys are matched by their <em>scope signature</em>, not by list position, because
     * Gradle re-sorts them. A key that keeps its id but widens its scope is the dangerous case and
     * is reported explicitly.
     */
    private void diffTrustedKeys(List<TrustedKey> olds, List<TrustedKey> news,
                                 List<MetadataChange> out) {
        Map<String, TrustedKey> oldById = new LinkedHashMap<>();
        for (TrustedKey k : olds) {
            oldById.put(keyIdent(k), k);
        }
        Map<String, TrustedKey> newById = new LinkedHashMap<>();
        for (TrustedKey k : news) {
            newById.put(keyIdent(k), k);
        }

        for (Map.Entry<String, TrustedKey> e : newById.entrySet()) {
            TrustedKey n = e.getValue();
            TrustedKey o = oldById.get(e.getKey());
            if (o == null) {
                // A brand-new trusted key. Unscoped ones can vouch for anything, including
                // artifacts added after this merge, so they are the worst case.
                out.add(new MetadataChange(
                        ChangeKind.ADDED, MetadataChange.Category.TRUSTED_KEY,
                        "trusted-key " + n.shortId(), null, null,
                        new MetadataChange.Detail.TrustedKeyChange(
                                null, n.id(), null, n.scopeDescription(), n.hasInlineKey()),
                        n.isUnscoped() ? MetadataChange.Severity.BLOCKER
                                : MetadataChange.Severity.REVIEW,
                        0, n.line()));
                continue;
            }
            boolean scopeChanged = !Objects.equals(o.scopeDescription(), n.scopeDescription());
            boolean keyMaterialAdded = !o.hasInlineKey() && n.hasInlineKey();
            boolean keyIdChanged = !Objects.equals(o.id(), n.id());
            if (scopeChanged || keyMaterialAdded || keyIdChanged) {
                boolean widened = n.isUnscoped() && !o.isUnscoped();
                out.add(new MetadataChange(
                        ChangeKind.MODIFIED, MetadataChange.Category.TRUSTED_KEY,
                        "trusted-key " + n.shortId(), null, null,
                        new MetadataChange.Detail.TrustedKeyChange(
                                o.id(), n.id(), o.scopeDescription(), n.scopeDescription(),
                                keyMaterialAdded),
                        widened || keyMaterialAdded ? MetadataChange.Severity.BLOCKER
                                : MetadataChange.Severity.REVIEW,
                        o.line(), n.line()));
            }
        }
        for (Map.Entry<String, TrustedKey> e : oldById.entrySet()) {
            if (!newById.containsKey(e.getKey())) {
                out.add(new MetadataChange(
                        ChangeKind.REMOVED, MetadataChange.Category.TRUSTED_KEY,
                        "trusted-key " + e.getValue().shortId(), null, null,
                        new MetadataChange.Detail.TrustedKeyChange(
                                e.getValue().id(), null, e.getValue().scopeDescription(), null,
                                false),
                        MetadataChange.Severity.INFO, e.getValue().line(), 0));
            }
        }
    }

    /**
     * Identity of a trusted key for diffing: the key id plus the scopes it covers. Two declarations
     * with the same id but different scope are different trust grants and must not collapse.
     */
    private static String keyIdent(TrustedKey k) {
        return (k.id() == null ? "" : k.id()) + "|" + k.scopeDescription();
    }

    // ------------------------------------------------------------------ small helpers

    private static Map<String, List<ComponentEntry>> groupByGa(
            Map<String, ComponentEntry> oldByGav, Map<String, ComponentEntry> newByGav,
            boolean removed) {
        Map<String, List<ComponentEntry>> out = new TreeMap<>();
        Map<String, ComponentEntry> source = removed ? oldByGav : newByGav;
        Map<String, ComponentEntry> other = removed ? newByGav : oldByGav;
        for (Map.Entry<String, ComponentEntry> e : source.entrySet()) {
            if (!other.containsKey(e.getKey())) {
                out.computeIfAbsent(e.getValue().coordinates().ga(), k -> new ArrayList<>())
                        .add(e.getValue());
            }
        }
        return out;
    }

    private static Map<String, ArtifactEntry> byName(List<ArtifactEntry> artifacts) {
        Map<String, ArtifactEntry> m = new LinkedHashMap<>();
        for (ArtifactEntry a : artifacts) {
            m.put(a.name(), a);
        }
        return m;
    }

    private static ArtifactEntry.Digest primary(List<ArtifactEntry.Digest> digests) {
        return digests.stream().filter(d -> !d.alsoTrust()).findFirst().orElse(null);
    }

    private static Set<String> alsoTrustValues(List<ArtifactEntry.Digest> digests) {
        Set<String> s = new LinkedHashSet<>();
        for (ArtifactEntry.Digest d : digests) {
            if (d.alsoTrust() && d.value() != null) {
                s.add(d.value());
            }
        }
        return s;
    }

    private static int lineOf(List<ArtifactEntry.Digest> digests, HashAlgorithm alg, String value) {
        for (ArtifactEntry.Digest d : digests) {
            if (d.algorithm() == alg && Objects.equals(d.value(), value)) {
                return d.line();
            }
        }
        return 0;
    }

    private static <T> List<T> minus(Set<T> a, Set<T> b) {
        Set<T> out = new LinkedHashSet<>(a);
        out.removeAll(b);
        return List.copyOf(out);
    }

    private static boolean looksLikeLocation(String origin) {
        if (origin == null) {
            return false;
        }
        String t = origin.trim().toLowerCase(java.util.Locale.ROOT);
        return t.contains("://") || t.startsWith("git@") || t.matches("^[a-z0-9.-]+\\.[a-z]{2,}(/.*)?$");
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static int severityRank(MetadataChange.Severity s) {
        return switch (s) {
            case BLOCKER -> 0;
            case REVIEW -> 1;
            case INFO -> 2;
        };
    }

    /**
     * A removed/added pair of the same {@code group:name} across two versions.
     *
     * <p>Correlating these is what keeps a routine bump from appearing as hundreds of alarming
     * changes. The pair is reported as one upgrade, and its digests are still verified individually.
     */
    public record Upgrade(ArtifactRef from, ArtifactRef to, int oldLine, int newLine) {
        public String ga() {
            return from.ga();
        }

        public String description() {
            return from.ga() + " " + from.version() + " → " + to.version();
        }
    }
}
