package io.depaudit.report;

import io.depaudit.AuditService;
import io.depaudit.verify.HttpRepositoryClient;
import io.depaudit.verify.RepositoryConfig;
import io.depaudit.verify.VerificationPolicy;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end report tests: parse two real files, diff, verify offline, and assert the report
 * surfaces the right things in the right order.
 */
class TextReportRendererTest {

    private static final Path FIXTURES = Path.of("src/test/resources/fixtures");

    private static AuditResult audit(String oldName, String newName) throws Exception {
        VerificationPolicy offline = new VerificationPolicy(
                List.of(RepositoryConfig.mavenCentral()), new HttpRepositoryClient(), true);
        return new AuditService().audit(FIXTURES.resolve(oldName), FIXTURES.resolve(newName), offline);
    }

    private static String render(AuditResult r) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        new TextReportRenderer(false, "gradle/verification-metadata.xml")
                .render(r, new PrintStream(buf, true, StandardCharsets.UTF_8));
        return buf.toString(StandardCharsets.UTF_8);
    }

    @Test
    void blockerIsRenderedFirstWithLineNumber() throws Exception {
        String out = render(audit("base.xml", "unscoped-key.xml"));

        assertTrue(out.contains("BLOCKING"), out);
        assertTrue(out.contains("trusted-key") || out.contains("trusted key"), out);
        assertTrue(out.contains("gradle/verification-metadata.xml:"),
                "a finding must point at a file:line: " + out);
        assertTrue(out.contains("RESULT: BLOCK"), out);

        int blocking = out.indexOf("BLOCKING");
        int footer = out.indexOf("RESULT:");
        assertTrue(blocking < footer);
    }

    @Test
    void alsoTrustInjectionIsCalledOut() throws Exception {
        String out = render(audit("base.xml", "also-trust-injected.xml"));
        assertTrue(out.contains("also-trust"), out);
        assertTrue(out.contains("RESULT: BLOCK"), out);
    }

    @Test
    void routineUpgradeIsSummarisedNotEnumerated() throws Exception {
        String out = render(audit("base.xml", "upgrade-ok.xml"));
        // Offline we cannot confirm upstream, so the upgrade shows as REVIEW rather than OK; the
        // important property is that it is one mention per upgrade, not a wall of line diffs.
        assertTrue(out.contains("commons-lang3"), out);
        assertTrue(out.contains("3.17.0") && out.contains("3.18.0"), out);
        int occurrences = countOccurrences(out, "commons-lang3-3.18.0.jar");
        assertTrue(occurrences <= 2,
                "a single upgrade must not be enumerated file by file in the summary: " + occurrences);
    }

    @Test
    void identicalFilesRenderAsPass() throws Exception {
        String out = render(audit("base.xml", "base.xml"));
        assertTrue(out.contains("RESULT: PASS"), out);
    }

    @Test
    void offlineModeIsStatedSoNobodyMistakesSilenceForConfirmation() throws Exception {
        String out = render(audit("base.xml", "tampered-same-version.xml"));
        assertTrue(out.contains("offline"), out);
        assertTrue(out.contains("unconfirmed") || out.contains("REVIEW"), out);
    }

    @Test
    void annotationsExcludeInformationalNoise() throws Exception {
        AuditResult r = audit("base.xml", "tampered-same-version.xml");
        List<String> annotations = TextReportRenderer.annotationLines(r);
        assertTrue(annotations.stream().anyMatch(a -> a.contains("unconfirmed")
                        || a.contains("CONTRADICTED")),
                annotations.toString());
        assertTrue(annotations.stream().noneMatch(a -> a.contains("n/a")),
                annotations.toString());
    }

    @Test
    void auditResultKeepsRoutineAndAttentionSeparate() throws Exception {
        AuditResult r = audit("base.xml", "upgrade-ok.xml");
        assertFalse(r.isBlocking(), "an offline upgrade is not a block");
        assertTrue(r.upgradesNeedingAttention() > 0,
                "offline, an upgrade is unconfirmed and needs a human");
    }

    @Test
    void blockingWhenBlockerIsUnconfirmed() throws Exception {
        // Offline, an unscoped trusted key cannot be "confirmed" by any repository, so the audit
        // must still block on the change itself rather than wait for verification.
        AuditResult r = audit("base.xml", "unscoped-key.xml");
        assertTrue(r.isBlocking());
        assertTrue(r.blockers().size() >= 1);
    }

    @Test
    void neverSaysPassWhileAnUpgradeIsUnconfirmed() throws Exception {
        // Safety-critical invariant: "PASS" means every change was positively accounted for. An
        // upgrade that could not be checked offline is a review item, and the footer must not
        // claim otherwise even though nothing contradicts a source.
        String out = render(audit("base.xml", "upgrade-ok.xml"));
        assertTrue(out.contains("REVIEW") || out.contains("BLOCK"), out);
        assertFalse(out.contains("RESULT: PASS"),
                "an unconfirmed upgrade must not be reported as a pass: " + out);
    }

    @Test
    void passOnlyWhenNothingNeedsAttention() throws Exception {
        // The identical-file case has genuinely nothing to look at, so PASS is correct there.
        String out = render(audit("base.xml", "base.xml"));
        assertTrue(out.contains("RESULT: PASS"), out);
    }

    @Test
    void eachFindingAppearsUnderExactlyOneHeading() throws Exception {
        // A single tampered hash produces a digest change and an origin change; a single
        // contradicted upgrade must not appear both as blocking and as "needs review". Either
        // would make one problem look like several and train reviewers to skim.
        String out = render(audit("base.xml", "unscoped-key.xml"));
        long keyMentions = out.lines()
                .filter(l -> l.contains("trusted key") && l.contains("11112222"))
                .count();
        assertEquals(1, keyMentions,
                "a blocking trusted-key edit must be reported once, not once per section: " + out);
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }
}
