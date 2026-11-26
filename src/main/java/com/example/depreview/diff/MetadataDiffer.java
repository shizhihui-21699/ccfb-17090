package com.example.depreview.diff;

import com.example.depreview.model.ArtifactMutation;
import com.example.depreview.model.Coordinates;
import com.example.depreview.model.HashChange;
import com.example.depreview.model.HashValue;
import com.example.depreview.model.MetadataRecord;
import com.example.depreview.model.MetadataSnapshot;
import com.example.depreview.model.MutationKind;
import com.example.depreview.model.SignerChange;
import com.example.depreview.model.SignerRef;
import com.example.depreview.model.SourceRef;
import com.example.depreview.model.UrlChange;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Semantic diff of two verification-metadata snapshots.
 *
 * <p>A line diff is a poor abstraction for a several-thousand-line XML file: a normal upgrade
 * removes one component version and adds another. This class pairs those records by group,
 * artifact and classifier/extension so the report describes an upgrade train instead of hundreds
 * of unrelated line edits.
 */
public final class MetadataDiffer {

    public List<ArtifactMutation> diff(MetadataSnapshot oldSnapshot, MetadataSnapshot newSnapshot) {
        Map<String, Map<String, Map<String, MetadataRecord>>> oldIndex = index(oldSnapshot);
        Map<String, Map<String, Map<String, MetadataRecord>>> newIndex = index(newSnapshot);
        String file = newSnapshot.path() != null ? newSnapshot.path().toString()
                : oldSnapshot.path() != null ? oldSnapshot.path().toString() : "verification-metadata.xml";

        Set<String> gas = new TreeSet<>();
        gas.addAll(oldIndex.keySet());
        gas.addAll(newIndex.keySet());

        List<ArtifactMutation> mutations = new ArrayList<>();
        for (String ga : gas) {
            Map<String, Map<String, MetadataRecord>> oldVersions =
                    oldIndex.getOrDefault(ga, Map.of());
            Map<String, Map<String, MetadataRecord>> newVersions =
                    newIndex.getOrDefault(ga, Map.of());

            Set<String> versions = new TreeSet<>();
            versions.addAll(oldVersions.keySet());
            versions.addAll(newVersions.keySet());

            List<String> oldOnlyVersions = new ArrayList<>();
            List<String> newOnlyVersions = new ArrayList<>();

            for (String version : versions) {
                Map<String, MetadataRecord> oldArtifacts = oldVersions.get(version);
                Map<String, MetadataRecord> newArtifacts = newVersions.get(version);
                if (oldArtifacts != null && newArtifacts != null) {
                    diffSameVersion(ga, version, oldArtifacts, newArtifacts, file, mutations);
                } else if (oldArtifacts != null) {
                    oldOnlyVersions.add(version);
                } else {
                    newOnlyVersions.add(version);
                }
            }

            pairVersionChanges(ga, oldOnlyVersions, newOnlyVersions,
                    oldVersions, newVersions, file, mutations);
        }

        mutations.sort(Comparator
                .comparing((ArtifactMutation m) -> m.primaryCoordinates() == null ? "" : m.primaryCoordinates().gav())
                .thenComparing(m -> m.stableArtifact() == null ? "" : m.stableArtifact())
                .thenComparing(m -> m.kind().name()));
        return List.copyOf(mutations);
    }

    private static Map<String, Map<String, Map<String, MetadataRecord>>> index(MetadataSnapshot snapshot) {
        Map<String, Map<String, Map<String, MetadataRecord>>> byGa = new TreeMap<>();
        if (snapshot == null) {
            return byGa;
        }
        for (MetadataRecord record : snapshot.records()) {
            Coordinates c = record.coordinates();
            byGa.computeIfAbsent(c.ga(), ignored -> new TreeMap<>())
                    .computeIfAbsent(c.version(), ignored -> new LinkedHashMap<>())
                    .put(record.stableKey(), record);
        }
        return byGa;
    }

    private void diffSameVersion(
            String ga,
            String version,
            Map<String, MetadataRecord> oldArtifacts,
            Map<String, MetadataRecord> newArtifacts,
            String file,
            List<ArtifactMutation> out) {

        Set<String> keys = new TreeSet<>();
        keys.addAll(oldArtifacts.keySet());
        keys.addAll(newArtifacts.keySet());

        for (String key : keys) {
            MetadataRecord oldRecord = oldArtifacts.get(key);
            MetadataRecord newRecord = newArtifacts.get(key);
            if (oldRecord == null) {
                out.add(simpleMutation(file, MutationKind.ADDED, null, newRecord));
            } else if (newRecord == null) {
                out.add(simpleMutation(file, MutationKind.REMOVED, oldRecord, null));
            } else {
                ArtifactMutation mutation = compareRecords(
                        file, MutationKind.SAME_VERSION, oldRecord, newRecord);
                if (mutation != null) {
                    out.add(mutation);
                }
            }
        }
    }

    private void pairVersionChanges(
            String ga,
            List<String> oldOnlyVersions,
            List<String> newOnlyVersions,
            Map<String, Map<String, MetadataRecord>> oldVersions,
            Map<String, Map<String, MetadataRecord>> newVersions,
            String file,
            List<ArtifactMutation> out) {

        // Normal MR case: one old version and one new version. Pair every artifact by
        // classifier/extension, producing one upgrade-train row per artifact.
        if (oldOnlyVersions.size() == 1 && newOnlyVersions.size() == 1) {
            String oldVersion = oldOnlyVersions.get(0);
            String newVersion = newOnlyVersions.get(0);
            MutationKind kind = VersionOrder.isUpgrade(oldVersion, newVersion)
                    ? MutationKind.VERSION_UPGRADE
                    : MutationKind.VERSION_DOWNGRADE;
            pairArtifactMaps(file, kind,
                    oldVersions.get(oldVersion), newVersions.get(newVersion), out);
            return;
        }

        // Less common: multiple retained versions or a partial metadata regeneration. Zip sorted
        // candidates where possible and report leftovers explicitly instead of dropping them.
        int pairs = Math.min(oldOnlyVersions.size(), newOnlyVersions.size());
        for (int i = 0; i < pairs; i++) {
            String oldVersion = oldOnlyVersions.get(i);
            String newVersion = newOnlyVersions.get(i);
            MutationKind kind = VersionOrder.isUpgrade(oldVersion, newVersion)
                    ? MutationKind.VERSION_UPGRADE
                    : MutationKind.VERSION_DOWNGRADE;
            pairArtifactMaps(file, kind,
                    oldVersions.get(oldVersion), newVersions.get(newVersion), out);
        }
        for (int i = pairs; i < newOnlyVersions.size(); i++) {
            Map<String, MetadataRecord> artifacts = newVersions.get(newOnlyVersions.get(i));
            artifacts.values().forEach(r -> out.add(simpleMutation(
                    file, MutationKind.NEW_VERSION_PARALLEL, null, r)));
        }
        for (int i = pairs; i < oldOnlyVersions.size(); i++) {
            Map<String, MetadataRecord> artifacts = oldVersions.get(oldOnlyVersions.get(i));
            artifacts.values().forEach(r -> out.add(simpleMutation(
                    file, MutationKind.REMOVED, r, null)));
        }
    }

    private void pairArtifactMaps(
            String file,
            MutationKind kind,
            Map<String, MetadataRecord> oldArtifacts,
            Map<String, MetadataRecord> newArtifacts,
            List<ArtifactMutation> out) {

        Set<String> keys = new TreeSet<>();
        keys.addAll(oldArtifacts.keySet());
        keys.addAll(newArtifacts.keySet());
        for (String key : keys) {
            MetadataRecord oldRecord = oldArtifacts.get(key);
            MetadataRecord newRecord = newArtifacts.get(key);
            if (oldRecord == null) {
                out.add(simpleMutation(file, MutationKind.ADDED, null, newRecord));
            } else if (newRecord == null) {
                out.add(simpleMutation(file, MutationKind.REMOVED, oldRecord, null));
            } else {
                ArtifactMutation mutation = compareRecords(file, kind, oldRecord, newRecord);
                if (mutation != null) {
                    out.add(mutation);
                }
            }
        }
    }

    private ArtifactMutation compareRecords(
            String file,
            MutationKind kind,
            MetadataRecord oldRecord,
            MetadataRecord newRecord) {

        List<HashChange> hashChanges = diffHashes(oldRecord, newRecord);
        List<UrlChange> urlChanges = diffUrls(oldRecord, newRecord);
        List<SignerChange> signerChanges = diffSigners(oldRecord, newRecord);

        // For version changes, retain the pair even when Gradle represented the algorithm set
        // differently; the verification stage still checks every new hash.
        if (kind == MutationKind.SAME_VERSION
                && hashChanges.isEmpty() && urlChanges.isEmpty() && signerChanges.isEmpty()) {
            return null;
        }

        return new ArtifactMutation(
                file,
                kind,
                oldRecord,
                newRecord,
                oldRecord.coordinates(),
                newRecord.coordinates(),
                newRecord.stableKey(),
                hashChanges,
                urlChanges,
                signerChanges);
    }

    private static ArtifactMutation simpleMutation(
            String file, MutationKind kind, MetadataRecord oldRecord, MetadataRecord newRecord) {
        MetadataRecord primary = newRecord != null ? newRecord : oldRecord;
        return new ArtifactMutation(
                file,
                kind,
                oldRecord,
                newRecord,
                oldRecord == null ? null : oldRecord.coordinates(),
                newRecord == null ? null : newRecord.coordinates(),
                primary == null ? "" : primary.stableKey(),
                List.of(),
                List.of(),
                List.of());
    }

    private List<HashChange> diffHashes(MetadataRecord oldRecord, MetadataRecord newRecord) {
        Set<String> algorithms = new TreeSet<>();
        algorithms.addAll(oldRecord.hashes().keySet());
        algorithms.addAll(newRecord.hashes().keySet());
        List<HashChange> changes = new ArrayList<>();
        for (String algorithm : algorithms) {
            HashValue oldHash = firstHash(oldRecord.hashes().get(algorithm));
            HashValue newHash = firstHash(newRecord.hashes().get(algorithm));
            String oldValue = oldHash == null ? null : oldHash.value();
            String newValue = newHash == null ? null : newHash.value();
            if (!java.util.Objects.equals(oldValue, newValue)) {
                changes.add(new HashChange(
                        algorithm,
                        oldValue,
                        newValue,
                        oldHash == null ? null : oldHash.line(),
                        newHash == null ? null : newHash.line()));
            }

            Set<String> oldAlso = oldHash == null ? Set.of() : new TreeSet<>(oldHash.alsoTrust());
            Set<String> newAlso = newHash == null ? Set.of() : new TreeSet<>(newHash.alsoTrust());
            for (String value : new TreeSet<>(newAlso)) {
                if (!oldAlso.contains(value)) {
                    changes.add(new HashChange(algorithm + " also-trust", null, value,
                            newHash == null ? null : newHash.line(),
                            newHash == null ? null : newHash.line()));
                }
            }
            for (String value : new TreeSet<>(oldAlso)) {
                if (!newAlso.contains(value)) {
                    changes.add(new HashChange(algorithm + " also-trust", value, null,
                            oldHash == null ? null : oldHash.line(),
                            oldHash == null ? null : oldHash.line()));
                }
            }
        }
        return changes;
    }

    private static HashValue firstHash(List<HashValue> hashes) {
        return hashes == null || hashes.isEmpty() ? null : hashes.get(0);
    }

    private List<UrlChange> diffUrls(MetadataRecord oldRecord, MetadataRecord newRecord) {
        List<SourceRef> oldUrls = oldRecord.sources().stream()
                .filter(s -> s.url() != null && !s.url().isBlank())
                .toList();
        List<SourceRef> newUrls = newRecord.sources().stream()
                .filter(s -> s.url() != null && !s.url().isBlank())
                .toList();

        Set<String> newUrlValues = new TreeSet<>();
        newUrls.forEach(u -> newUrlValues.add(normalizeUrl(u.url())));
        Set<String> oldUrlValues = new TreeSet<>();
        oldUrls.forEach(u -> oldUrlValues.add(normalizeUrl(u.url())));

        List<SourceRef> removed = oldUrls.stream()
                .filter(u -> !newUrlValues.contains(normalizeUrl(u.url())))
                .toList();
        List<SourceRef> added = newUrls.stream()
                .filter(u -> !oldUrlValues.contains(normalizeUrl(u.url())))
                .toList();

        List<UrlChange> changes = new ArrayList<>();
        int pairs = Math.min(removed.size(), added.size());
        for (int i = 0; i < pairs; i++) {
            changes.add(new UrlChange(
                    removed.get(i).url(), added.get(i).url(),
                    removed.get(i).line(), added.get(i).line()));
        }
        for (int i = pairs; i < removed.size(); i++) {
            changes.add(new UrlChange(removed.get(i).url(), null, removed.get(i).line(), null));
        }
        for (int i = pairs; i < added.size(); i++) {
            changes.add(new UrlChange(null, added.get(i).url(), null, added.get(i).line()));
        }
        return changes;
    }

    private List<SignerChange> diffSigners(MetadataRecord oldRecord, MetadataRecord newRecord) {
        Map<String, Integer> oldIds = new LinkedHashMap<>();
        oldRecord.signers().forEach(s -> oldIds.putIfAbsent(s.keyId(), s.line()));
        Map<String, Integer> newIds = new LinkedHashMap<>();
        newRecord.signers().forEach(s -> newIds.putIfAbsent(s.keyId(), s.line()));

        List<String> removed = oldIds.keySet().stream().filter(k -> !newIds.containsKey(k)).sorted().toList();
        List<String> added = newIds.keySet().stream().filter(k -> !oldIds.containsKey(k)).sorted().toList();
        List<SignerChange> changes = new ArrayList<>();
        int pairs = Math.min(removed.size(), added.size());
        for (int i = 0; i < pairs; i++) {
            changes.add(new SignerChange(
                    removed.get(i), added.get(i), oldIds.get(removed.get(i)), newIds.get(added.get(i))));
        }
        for (int i = pairs; i < removed.size(); i++) {
            changes.add(new SignerChange(removed.get(i), null, oldIds.get(removed.get(i)), null));
        }
        for (int i = pairs; i < added.size(); i++) {
            changes.add(new SignerChange(null, added.get(i), null, newIds.get(added.get(i))));
        }
        return changes;
    }

    private static String normalizeUrl(String url) {
        if (url == null) {
            return "";
        }
        return url.trim().replaceAll("/+$", "");
    }
}
