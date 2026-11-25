package io.depaudit.diff;

import java.util.List;

/**
 * Result of diffing two metadata revisions.
 *
 * @param changes  every individual change, ordered most severe first
 * @param upgrades correlated version bumps (the "normal churn" the tool must not shout about)
 */
public record MetadataDiff(List<MetadataChange> changes, List<MetadataDiffer.Upgrade> upgrades) {

    public MetadataDiff {
        changes = changes == null ? List.of() : List.copyOf(changes);
        upgrades = upgrades == null ? List.of() : List.copyOf(upgrades);
    }

    public List<MetadataChange> blockers() {
        return changes.stream().filter(MetadataChange::isBlocker).toList();
    }

    public List<MetadataChange> needingReview() {
        return changes.stream()
                .filter(c -> c.severity() == MetadataChange.Severity.REVIEW)
                .toList();
    }
}
