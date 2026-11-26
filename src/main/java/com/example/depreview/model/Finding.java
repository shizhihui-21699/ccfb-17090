package com.example.depreview.model;

import com.example.depreview.verify.VerificationResult;

import java.util.ArrayList;
import java.util.List;

public final class Finding {
    private final String id;
    private final Severity severity;
    private final String title;
    private final String file;
    private final String groupId;
    private final String artifactId;
    private final String version;
    private final String oldVersion;
    private final String artifactName;
    private final MutationKind kind;
    private final List<String> changes;
    private final List<String> evidenceLines;
    private final String recommendation;
    private final BuildEvidence buildEvidence;
    private final VerificationResult verification;

    private Finding(Builder b) {
        this.id = b.id;
        this.severity = b.severity;
        this.title = b.title;
        this.file = b.file;
        this.groupId = b.groupId;
        this.artifactId = b.artifactId;
        this.version = b.version;
        this.oldVersion = b.oldVersion;
        this.artifactName = b.artifactName;
        this.kind = b.kind;
        this.changes = List.copyOf(b.changes);
        this.evidenceLines = List.copyOf(b.evidenceLines);
        this.recommendation = b.recommendation;
        this.buildEvidence = b.buildEvidence;
        this.verification = b.verification;
    }

    public static Builder builder(String id, Severity severity, String title) {
        return new Builder(id, severity, title);
    }

    public String getId() { return id; }
    public Severity getSeverity() { return severity; }
    public String getTitle() { return title; }
    public String getFile() { return file; }
    public String getGroupId() { return groupId; }
    public String getArtifactId() { return artifactId; }
    public String getVersion() { return version; }
    public String getOldVersion() { return oldVersion; }
    public String getArtifactName() { return artifactName; }
    public MutationKind getKind() { return kind; }
    public List<String> getChanges() { return changes; }
    public List<String> getEvidenceLines() { return evidenceLines; }
    public String getRecommendation() { return recommendation; }
    public BuildEvidence getBuildEvidence() { return buildEvidence; }
    public VerificationResult getVerification() { return verification; }

    public String coordinateLabel() {
        String ga = groupId + ":" + artifactId;
        if (oldVersion != null && version != null && !oldVersion.equals(version)) {
            return ga + ":" + oldVersion + " -> " + version;
        }
        return ga + ":" + version;
    }

    public static final class Builder {
        private final String id;
        private final Severity severity;
        private final String title;
        private String file = "";
        private String groupId = "";
        private String artifactId = "";
        private String version = "";
        private String oldVersion = "";
        private String artifactName = "";
        private MutationKind kind = MutationKind.SAME_VERSION;
        private final List<String> changes = new ArrayList<>();
        private final List<String> evidenceLines = new ArrayList<>();
        private String recommendation = "";
        private BuildEvidence buildEvidence;
        private VerificationResult verification;

        private Builder(String id, Severity severity, String title) {
            this.id = id;
            this.severity = severity;
            this.title = title;
        }

        public Builder mutation(ArtifactMutation mutation) {
            this.file = mutation.metadataFile();
            this.kind = mutation.kind();
            Coordinates now = mutation.newCoordinates();
            Coordinates old = mutation.oldCoordinates();
            Coordinates primary = mutation.primaryCoordinates();
            if (primary != null) {
                this.groupId = primary.groupId();
                this.artifactId = primary.artifactId();
            }
            if (now != null) this.version = now.version();
            if (old != null) this.oldVersion = old.version();
            if (mutation.primaryRecord() != null) {
                this.artifactName = mutation.primaryRecord().artifactName();
            }
            return this;
        }

        public Builder file(String file) { this.file = file; return this; }
        public Builder coordinates(Coordinates c) {
            this.groupId = c.groupId();
            this.artifactId = c.artifactId();
            this.version = c.version();
            return this;
        }
        public Builder oldVersion(String v) { this.oldVersion = v; return this; }
        public Builder artifactName(String v) { this.artifactName = v; return this; }
        public Builder kind(MutationKind k) { this.kind = k; return this; }
        public Builder addChange(String change) { this.changes.add(change); return this; }
        public Builder addEvidenceLine(String line) { this.evidenceLines.add(line); return this; }
        public Builder recommendation(String recommendation) {
            this.recommendation = recommendation;
            return this;
        }
        public Builder buildEvidence(BuildEvidence evidence) {
            this.buildEvidence = evidence;
            return this;
        }
        public Builder verification(VerificationResult verification) {
            this.verification = verification;
            return this;
        }

        public Finding build() {
            return new Finding(this);
        }
    }
}
