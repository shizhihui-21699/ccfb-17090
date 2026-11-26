package com.example.depreview.diff;

import com.example.depreview.model.BuildEvidence;
import com.example.depreview.model.Coordinates;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BuildCorrelatorTest {

    @Test
    void detectsGradleCoordinateVersionBump() {
        String patch = """
                diff --git a/build.gradle.kts b/build.gradle.kts
                --- a/build.gradle.kts
                +++ b/build.gradle.kts
                @@ -1,3 +1,3 @@
                dependencies {
                -  implementation("com.acme:widget:1.0.0")
                +  implementation("com.acme:widget:2.0.0")
                   implementation("com.acme:unchanged:1.0.0")
                }
                """;
        UnifiedDiffParser.Patch parsed = new UnifiedDiffParser().parse(patch);
        BuildEvidence evidence = new BuildCorrelator(parsed)
                .correlate(new Coordinates("com.acme", "widget", "1.0.0"),
                        new Coordinates("com.acme", "widget", "2.0.0"));

        assertTrue(evidence.buildPatchProvided());
        assertTrue(evidence.newVersionDeclared());
        assertTrue(evidence.oldVersionRemoved());
        assertFalse(evidence.matchingLines().isEmpty());
    }
}
