package com.example.depreview.model;

import java.util.List;

public record ArtifactMutation(
        String metadataFile,
        MutationKind kind,
        MetadataRecord oldRecord,
        MetadataRecord newRecord,
        Coordinates oldCoordinates,
        Coordinates newCoordinates,
        String stableArtifact,
        List<HashChange> hashChanges,
        List<UrlChange> urlChanges,
        List<SignerChange> signerChanges) {

    public Coordinates primaryCoordinates() {
        return newCoordinates != null ? newCoordinates : oldCoordinates;
    }

    public MetadataRecord primaryRecord() {
        return newRecord != null ? newRecord : oldRecord;
    }

    public String artifactNameSafe() {
        MetadataRecord record = primaryRecord();
        return record == null ? "" : record.artifactName();
    }

    public boolean hasSecurityRelevantChange() {
        return !hashChanges.isEmpty() || !urlChanges.isEmpty() || !signerChanges.isEmpty()
                || kind == MutationKind.ADDED;
    }
}
