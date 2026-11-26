package com.example.depreview.diff;

import com.example.depreview.model.BuildEvidence;
import com.example.depreview.model.Coordinates;

import java.util.ArrayList;
import java.util.List;

/**
 * Best-effort correlation with build-file diffs.
 *
 * <p>This is supporting evidence, not a requirement: a version can be upgraded through a BOM,
 * platform, dependency constraint or transitive management without a literal coordinate edit.
 */
public final class BuildCorrelator {

    private final UnifiedDiffParser.Patch patch;

    public BuildCorrelator(UnifiedDiffParser.Patch patch) {
        this.patch = patch;
    }

    public BuildEvidence correlate(Coordinates oldCoordinates, Coordinates newCoordinates) {
        if (patch == null || patch.files().isEmpty()) {
            return BuildEvidence.notProvided();
        }

        String artifactId = newCoordinates != null
                ? newCoordinates.artifactId()
                : oldCoordinates == null ? "" : oldCoordinates.artifactId();
        String groupId = newCoordinates != null
                ? newCoordinates.groupId()
                : oldCoordinates == null ? "" : oldCoordinates.groupId();
        String newVersion = newCoordinates == null ? null : newCoordinates.version();
        String oldVersion = oldCoordinates == null ? null : oldCoordinates.version();

        boolean newDeclared = false;
        boolean oldRemoved = false;
        List<String> matches = new ArrayList<>();

        for (UnifiedDiffParser.PatchFile file : patch.files()) {
            String path = file.newPath().isEmpty() ? file.oldPath() : file.newPath();
            boolean versionCatalog = path.endsWith("libs.versions.toml")
                    || path.endsWith("versions.properties");
            for (UnifiedDiffParser.Hunk hunk : file.hunks()) {
                String hunkText = hunk.lines().stream()
                        .map(UnifiedDiffParser.DiffLine::text)
                        .reduce("", (a, b) -> a + "\n" + b);
                boolean hunkMentionsArtifact = hunkText.contains(artifactId)
                        || hunkText.contains(groupId + ":" + artifactId)
                        || hunkText.contains(groupId.replace('.', '/') + "/" + artifactId);

                for (UnifiedDiffParser.DiffLine line : hunk.lines()) {
                    String text = line.text() == null ? "" : line.text().trim();
                    if (text.isEmpty()) {
                        continue;
                    }
                    if (line.kind() == UnifiedDiffParser.DiffLine.Kind.ADD
                            && newVersion != null
                            && lineLooksLikeVersion(text, newVersion)
                            && (hunkMentionsArtifact || versionCatalog
                                || directCoordinate(text, groupId, artifactId, newVersion))) {
                        newDeclared = true;
                        addMatch(matches, "+ " + text);
                    }
                    if (line.kind() == UnifiedDiffParser.DiffLine.Kind.REMOVE
                            && oldVersion != null
                            && lineLooksLikeVersion(text, oldVersion)
                            && (hunkMentionsArtifact || versionCatalog
                                || directCoordinate(text, groupId, artifactId, oldVersion))) {
                        oldRemoved = true;
                        addMatch(matches, "- " + text);
                    }
                }
            }
        }

        if (matches.isEmpty()) {
            return BuildEvidence.none();
        }
        return new BuildEvidence(true, newDeclared, oldRemoved, List.copyOf(matches));
    }

    private static boolean lineLooksLikeVersion(String line, String version) {
        if (line.contains(version)) {
            return true;
        }
        String quoted = "\"" + version + "\"";
        String singleQuoted = "'" + version + "'";
        return line.contains(quoted) || line.contains(singleQuoted);
    }

    private static boolean directCoordinate(String line, String group, String artifact, String version) {
        return line.contains(group + ":" + artifact + ":" + version)
                || line.contains(group + "/" + artifact + "/" + version)
                || (line.contains(group) && line.contains(artifact) && line.contains(version));
    }

    private static void addMatch(List<String> matches, String line) {
        if (matches.size() < 12 && !matches.contains(line)) {
            matches.add(line);
        }
    }
}
