package com.example.depreview.analyze;

import com.example.depreview.diff.UnifiedDiffParser;
import com.example.depreview.model.Finding;
import com.example.depreview.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyChangeAnalyzerTest {

    @Test
    void flagsDisablingSignaturesAndBroadTrustRule() {
        String patch = """
                diff --git a/gradle/verification-metadata.xml b/gradle/verification-metadata.xml
                --- a/gradle/verification-metadata.xml
                +++ b/gradle/verification-metadata.xml
                @@ -10,6 +10,8 @@
                   <configuration>
                -    <verify-signatures>true</verify-signatures>
                +    <verify-signatures>false</verify-signatures>
                     <trusted-artifacts>
                +      <trust group="com.example" name=".*" regex="true"/>
                     </trusted-artifacts>
                     <components>
                +      <sha1 value="1234567890abcdef1234567890abcdef12345678"/>
                @@
                +      <sha256 value="abcd"/>
                """;

        List<Finding> findings = new PolicyChangeAnalyzer()
                .analyze(new UnifiedDiffParser().parse(patch));

        assertTrue(findings.stream().anyMatch(f ->
                f.getSeverity() == Severity.CRITICAL && f.getTitle().contains("disabled")));
        assertTrue(findings.stream().anyMatch(f ->
                f.getSeverity() == Severity.CRITICAL && f.getTitle().contains("trusted-artifact")));
        assertTrue(findings.stream().anyMatch(f ->
                f.getSeverity() == Severity.MEDIUM && f.getTitle().contains("Weak checksum")));
        assertTrue(findings.stream().anyMatch(f ->
                f.getTitle().contains("Malformed sha256")));
    }
}
