package io.depaudit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The exit-code contract with CI.
 *
 * <p>Exit codes are not cosmetic here. A check that fails on every routine dependency bump gets
 * deleted from the pipeline within a week, and a deleted check catches nothing — so {@code 1}
 * ("a human should look") and {@code 2} ("do not merge") must stay distinct, and a tool error must
 * never be mistaken for either.
 */
class MainExitCodeTest {

    private static final Path FIXTURES = Path.of("src/test/resources/fixtures");

    private static int run(String... args) {
        return Main.run(args);
    }

    @Test
    void identicalFilesPass() {
        assertEquals(0, run("--old", FIXTURES.resolve("base.xml").toString(),
                "--new", FIXTURES.resolve("base.xml").toString(), "--offline", "--no-color"));
    }

    @Test
    void contradictionBlocksWithExit2() {
        assertEquals(2, run("--old", FIXTURES.resolve("base.xml").toString(),
                "--new", FIXTURES.resolve("unscoped-key.xml").toString(),
                "--offline", "--no-color"),
                "an unscoped trusted key must block even offline");
    }

    @Test
    void reviewNeedingChangeIsZeroWithoutFailOnReview() {
        // A routine upgrade, offline: nothing is proven wrong, so the default is 0. CI that wants
        // to gate on it opts in with --fail-on-review.
        assertEquals(0, run("--old", FIXTURES.resolve("base.xml").toString(),
                "--new", FIXTURES.resolve("upgrade-ok.xml").toString(), "--offline", "--no-color"));
    }

    @Test
    void reviewNeedingChangeIsOneWithFailOnReview() {
        assertEquals(1, run("--old", FIXTURES.resolve("base.xml").toString(),
                "--new", FIXTURES.resolve("upgrade-ok.xml").toString(),
                "--offline", "--fail-on-review", "--no-color"));
    }

    @Test
    void missingFileIsToolErrorExit3() {
        assertEquals(3, run("--old", "/nonexistent/nope.xml",
                "--new", FIXTURES.resolve("base.xml").toString(), "--offline", "--no-color"));
    }

    @Test
    void unparseableNewFileIsToolErrorExit3(@TempDir Path tmp) throws Exception {
        Path bad = tmp.resolve("bad.xml");
        Files.writeString(bad, "<verification-metadata><components>");
        assertEquals(3, run("--old", FIXTURES.resolve("base.xml").toString(),
                "--new", bad.toString(), "--offline", "--no-color"));
    }

    @Test
    void unknownOptionIsToolErrorExit3() {
        assertEquals(3, run("--not-a-flag"));
    }

    @Test
    void missingOldAndBaseIsToolErrorExit3() {
        assertEquals(3, run("--new", FIXTURES.resolve("base.xml").toString()));
    }

    @Test
    void oldAndBaseTogetherIsRejected() {
        assertEquals(3, run("--old", FIXTURES.resolve("base.xml").toString(),
                "--base", "HEAD", "--new", FIXTURES.resolve("base.xml").toString()));
    }

    @Test
    void helpExitsZero() {
        assertEquals(0, run("--help"));
    }

    @Test
    void repositoryTierParsing() {
        Main.Options o = Main.Options.parse(new String[]{
                "--old", "a", "--new", "b",
                "--repo", "central=https://repo1.maven.org/maven2@canonical",
                "--repo", "nexus=https://nexus.corp/repo@internal",
                "--repo", "arch=false://archive@mirror@offline"
        });
        assertEquals(3, o.repos.size());
        assertEquals(io.depaudit.verify.TrustTier.CANONICAL, o.repos.get(0).tier());
        assertEquals(io.depaudit.verify.TrustTier.INTERNAL, o.repos.get(1).tier());
        assertEquals(io.depaudit.verify.TrustTier.MIRROR, o.repos.get(2).tier());
        assertTrue(o.repos.get(2).offline());
    }

    @Test
    void badRepositorySpecIsRejected() {
        assertEquals(3, run("--old", "a", "--new", "b", "--repo", "no-equals-sign"));
        assertEquals(3, run("--old", "a", "--new", "b", "--repo", "id=url@bogus-tier"));
    }

    @Test
    void defaultRepositoryIsMavenCentral() {
        Main.Options o = Main.Options.parse(new String[]{"--old", "a", "--new", "b"});
        io.depaudit.verify.VerificationPolicy p = o.toPolicy();
        assertEquals(1, p.repositories().size());
        assertEquals("maven-central", p.repositories().get(0).id());
        assertEquals(io.depaudit.verify.TrustTier.CANONICAL, p.repositories().get(0).tier());
    }
}
