package io.depaudit.verify.pgp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Signature verification, exercised against real signed artifacts.
 *
 * <p>The fixtures are genuine: {@code commons-lang3-3.17.0.jar} is the published Apache artifact
 * and {@code apache-signing-key.asc} is the maintainer's public key as served by a keyserver. A
 * byte-flip in the payload must make verification fail, which is the property that actually matters.
 */
class PgpSignatureVerifierTest {

    private static final Path PGP = Path.of("src/test/resources/pgp");
    private final PgpSignatureVerifier verifier = new PgpSignatureVerifier();

    private static byte[] read(String name) throws Exception {
        return Files.readAllBytes(PGP.resolve(name));
    }

    @Test
    void verifiesRealApacheArtifactSignature() throws Exception {
        byte[] sig = read("commons-lang3-3.17.0.jar.asc");
        byte[] jar = read("commons-lang3-3.17.0.jar");
        byte[] key = read("apache-signing-key.asc");

        SignatureVerification r = verifier.verify(sig, jar, KeySource.fixed("pinned", key));

        assertTrue(r.valid(), r.error());
        assertEquals("86FDC7E2A11262CB", r.signerKeyId());
        assertEquals("2DB4F1EF0FA761ECC4EA935C86FDC7E2A11262CB", r.signerFingerprint());
        assertTrue(r.signerUserId().contains("Gary David Gregory"), r.signerUserId());
    }

    @Test
    void failsWhenArtifactBytesAreTamperedWith() throws Exception {
        byte[] sig = read("commons-lang3-3.17.0.jar.asc");
        byte[] jar = read("commons-lang3-3.17.0.jar");
        jar[1000] ^= 0x01;   // flip one bit deep inside the archive
        byte[] key = read("apache-signing-key.asc");

        SignatureVerification r = verifier.verify(sig, jar, KeySource.fixed("pinned", key));

        assertFalse(r.valid());
        assertNotNull(r.error());
        // The signer must still be reported: "these bytes are not what key X signed" is actionable.
        assertEquals("86FDC7E2A11262CB", r.signerKeyId());
    }

    @Test
    void failsWhenSignatureBlockIsTamperedWith() throws Exception {
        byte[] sig = read("payload.txt.asc");
        byte[] payload = read("payload.txt");
        byte[] key = read("test-key.asc");

        String armored = new String(sig, java.nio.charset.StandardCharsets.US_ASCII);
        // Corrupt characters inside the base64 body, not the armour headers.
        int bodyStart = armored.indexOf("\n\n") + 2;
        char[] chars = armored.toCharArray();
        for (int i = bodyStart; i < bodyStart + 8; i++) {
            chars[i] = chars[i] == 'A' ? 'B' : 'A';
        }
        byte[] broken = new String(chars).getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        SignatureVerification r = verifier.verify(broken, payload, KeySource.fixed("t", key));
        assertFalse(r.valid(), "a mangled signature block must not verify");
    }

    @Test
    void failsWhenPayloadIsDifferent() throws Exception {
        SignatureVerification r = verifier.verify(read("payload.txt.asc"), read("tampered.txt"),
                KeySource.fixed("t", read("test-key.asc")));
        assertFalse(r.valid());
        assertTrue(r.error().contains("does not match"), r.error());
    }

    @Test
    void reportsMissingKeyClearly() throws Exception {
        SignatureVerification r = verifier.verify(read("payload.txt.asc"), read("payload.txt"),
                KeySource.none());
        assertFalse(r.valid());
        assertTrue(r.error().contains("no public key"), r.error());
        assertTrue(r.consultedSources().stream().anyMatch(s -> s.contains("signature names key")),
                r.consultedSources().toString());
    }

    @Test
    void wrongKeyDoesNotVerify() throws Exception {
        // Signature made by the test key, but only the Apache key is offered.
        SignatureVerification r = verifier.verify(read("payload.txt.asc"), read("payload.txt"),
                KeySource.fixed("wrong", read("apache-signing-key.asc")));
        assertFalse(r.valid(), "a signature must not verify against an unrelated key");
    }

    @Test
    void emptySignatureBlockIsRejected() {
        SignatureVerification r = verifier.verify(new byte[0], "x".getBytes(), KeySource.none());
        assertFalse(r.valid());
    }

    @Test
    void describeExposesKeyMetadata() throws Exception {
        var info = verifier.describe(read("test-key.asc"));
        assertTrue(info.isPresent());
        assertEquals("64E14832E531EB192466A0FD3CCA0C2A8CFD1773", info.get().fingerprint());
        assertTrue(info.get().userId().contains("depaudit test"));
    }

    @Test
    void keyMatchingHandlesFingerprintsAndLongIds() {
        String fp = "2DB4F1EF0FA761ECC4EA935C86FDC7E2A11262CB";
        String shortId = "86FDC7E2A11262CB";

        assertTrue(PgpSignatureVerifier.keyMatches(fp, fp, shortId),
                "full fingerprint in the file matches");
        assertTrue(PgpSignatureVerifier.keyMatches(shortId, fp, shortId),
                "long key id in the file matches");
        assertTrue(PgpSignatureVerifier.keyMatches(fp.toLowerCase(), fp, shortId),
                "case-insensitive");
        assertFalse(PgpSignatureVerifier.keyMatches("0000000000000000", fp, shortId));
        assertFalse(PgpSignatureVerifier.keyMatches(null, fp, shortId));
    }

    @Test
    void keyringSourceLoadsAndServesKeys(@TempDir Path tmp) throws Exception {
        Path ring = tmp.resolve("trusted.gpg");
        Files.write(ring, read("apache-signing-key.asc"));

        KeyringKeySource src = KeyringKeySource.load(ring);
        assertTrue(src.size() > 0);
        assertTrue(src.fetch("86FDC7E2A11262CB").isPresent(), "long id resolves");
        assertTrue(src.fetch("2DB4F1EF0FA761ECC4EA935C86FDC7E2A11262CB").isPresent(),
                "full fingerprint resolves");
        assertTrue(src.fetch("0000000000000000").isEmpty());
        assertTrue(src.name().contains("trusted.gpg"));
    }

    @Test
    void keyringSourceRejectsNonKeyFile(@TempDir Path tmp) throws Exception {
        Path notAKey = tmp.resolve("junk.asc");
        Files.writeString(notAKey, "this is not a key");
        org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class,
                () -> KeyringKeySource.load(notAKey));
    }

    @Test
    void chainedKeySourceFallsThrough() throws Exception {
        KeySource chained = KeySource.chain(java.util.List.of(
                KeySource.fixed("first", read("test-key.asc")),
                KeySource.fixed("second", read("apache-signing-key.asc"))));

        assertTrue(chained.name().contains("first"));
        assertTrue(chained.fetch("86FDC7E2A11262CB").isPresent());
    }
}
