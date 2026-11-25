package io.depaudit.report;

import io.depaudit.AuditService;
import io.depaudit.verify.VerificationPolicy;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

class JsonReportRendererTest {

    private static final Path FIXTURES = Path.of("src/test/resources/fixtures");

    private static String renderJson(String oldName, String newName) throws Exception {
        VerificationPolicy offline = VerificationPolicy.offlineWith(
                java.util.List.of(), new io.depaudit.verify.HttpRepositoryClient());
        AuditResult r = new AuditService()
                .audit(FIXTURES.resolve(oldName), FIXTURES.resolve(newName), offline);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        new JsonReportRenderer().render(r, new PrintStream(buf, true, StandardCharsets.UTF_8));
        return buf.toString(StandardCharsets.UTF_8);
    }

    @Test
    void producesParseableJson() throws Exception {
        // A tiny hand-rolled parser assertion is not enough here: the point of JSON output is that
        // CI can consume it, so it must be well-formed. Python's json module is the referee.
        String json = renderJson("base.xml", "tampered-same-version.xml");
        java.nio.file.Path tmp = java.nio.file.Files.createTempFile("report-", ".json");
        java.nio.file.Files.writeString(tmp, json);
        try {
            Process p = new ProcessBuilder("python3", "-I", "-c",
                    "import json,sys; d=json.load(open(sys.argv[1])); "
                            + "print(len(d['changes']), str(d['blocking']).lower())",
                    tmp.toString()).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            assertTrue(p.waitFor() == 0, "json did not parse: " + out);
            assertTrue(out.endsWith("true"), out);
        } finally {
            java.nio.file.Files.deleteIfExists(tmp);
        }
    }

    @Test
    void rendersRequiredTopLevelFields() throws Exception {
        String json = renderJson("base.xml", "upgrade-ok.xml");
        for (String field : new String[]{
                "\"oldSource\"", "\"newSource\"", "\"offline\"", "\"blocking\"",
                "\"summary\"", "\"changes\"", "\"upgrades\""}) {
            assertTrue(json.contains(field), "missing " + field + " in " + json);
        }
    }

    @Test
    void rendersUpgradeEntries() throws Exception {
        String json = renderJson("base.xml", "upgrade-ok.xml");
        assertTrue(json.contains("\"from\""), json);
        assertTrue(json.contains("commons-lang3:3.17.0"), json);
        assertTrue(json.contains("commons-lang3:3.18.0"), json);
    }

    @Test
    void escapesQuotesAndControlCharacters() {
        assertTrue(JsonReportRenderer.q("a\"b").equals("\"a\\\"b\""));
        assertTrue(JsonReportRenderer.q("a\nb").equals("\"a\\nb\""));
        assertTrue(JsonReportRenderer.q("a\\b").equals("\"a\\\\b\""));
        assertTrue(JsonReportRenderer.q(null).equals("null"));
        assertFalse(JsonReportRenderer.q("\u0001").contains("\u0001"));
    }
}
