package com.example.depreview.diff;

import com.example.depreview.gradle.GradleMetadataParser;
import com.example.depreview.model.ArtifactMutation;
import com.example.depreview.model.MutationKind;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MetadataDifferFixtureTest {

    @Test
    void pairsVersionUpgradesAndFindsSameVersionTampering() throws Exception {
        GradleMetadataParser parser = new GradleMetadataParser();
        var oldSnapshot = parser.parse(Path.of(
                "test-fixtures/before/gradle/verification-metadata.xml")).snapshot();
        var newSnapshot = parser.parse(Path.of(
                "test-fixtures/after/gradle/verification-metadata.xml")).snapshot();

        List<ArtifactMutation> mutations = new MetadataDiffer().diff(oldSnapshot, newSnapshot);

        assertEquals(4, mutations.size());
        assertTrue(mutations.stream().anyMatch(m ->
                m.kind() == MutationKind.VERSION_UPGRADE
                        && m.primaryCoordinates().gav().equals("com.acme:widget-lib:1.5.0")
                        && m.artifactNameSafe().equals("widget-lib-1.5.0.jar")));
        assertTrue(mutations.stream().anyMatch(m ->
                m.kind() == MutationKind.VERSION_UPGRADE
                        && m.primaryCoordinates().gav().equals("com.internal:billing-client:3.0.0")));

        ArtifactMutation attack = mutations.stream()
                .filter(m -> "com.acme:auth-core".equals(
                        m.primaryCoordinates().groupId() + ":" + m.primaryCoordinates().artifactId()))
                .findFirst().orElseThrow();
        assertEquals(MutationKind.SAME_VERSION, attack.kind());
        assertFalse(attack.hashChanges().isEmpty());
        assertTrue(attack.hashChanges().get(0).valueChanged());
        assertEquals(1, attack.urlChanges().size());
        assertTrue(attack.urlChanges().get(0).newUrl().contains("evil-download.example.io"));
    }
}
