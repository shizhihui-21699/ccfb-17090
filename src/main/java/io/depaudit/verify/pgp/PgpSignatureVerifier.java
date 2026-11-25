package io.depaudit.verify.pgp;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Verifies detached PGP signatures (the {@code .asc} files Maven repositories publish).
 *
 * <p>Two separate questions are answered, and conflating them is the classic mistake:
 *
 * <ol>
 *   <li><b>Is the signature cryptographically valid for these bytes?</b> — answered here, and it
 *       only proves that whoever holds the private key for the signing key signed this data.</li>
 *   <li><b>Is that key allowed to vouch for this artifact?</b> — answered by the caller against the
 *       trusted-key set. A perfectly valid signature by a key nobody trusts is not a pass.</li>
 * </ol>
 *
 * <p>So a {@code valid} result here is necessary but not sufficient; the verification layer must
 * still decide whether the signer is trusted for the coordinates in question.
 */
public final class PgpSignatureVerifier {

    static {
        // Ensure the JCA provider used by the verifier builder is present; registering it once here
        // keeps callers from having to know BouncyCastle's provider plumbing.
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * Verifies a detached, armored signature over {@code artifactBytes}.
     *
     * @param signatureBlock the {@code .asc} contents (armored or binary)
     * @param artifactBytes  the file the signature is supposed to cover
     * @param keys           where to get the signer's public key
     */
    public SignatureVerification verify(byte[] signatureBlock, byte[] artifactBytes, KeySource keys) {
        List<String> sources = new ArrayList<>();
        PGPSignature signature;
        try {
            signature = firstSignature(signatureBlock);
        } catch (IOException | PGPException e) {
            return SignatureVerification.failure("unreadable signature block: " + e.getMessage(), sources);
        }
        if (signature == null) {
            return SignatureVerification.failure("signature block contained no signature", sources);
        }
        long keyId = signature.getKeyID();
        String keyIdHex = Long.toHexString(keyId).toUpperCase(Locale.ROOT);

        Optional<PGPPublicKey> key = Optional.empty();
        try {
            sources.add("signature names key " + pad(keyIdHex));
            Optional<byte[]> keyMaterial = keys.fetch(pad(keyIdHex));
            if (keyMaterial.isEmpty()) {
                return SignatureVerification.failure(
                        "no public key available for " + pad(keyIdHex)
                                + " (tried " + keys.name() + ")", sources);
            }
            sources.add("key material from " + keys.name());
            key = findKey(keyMaterial.get(), keyId);
            if (key.isEmpty()) {
                return SignatureVerification.failure(
                        "key " + pad(keyIdHex) + " not present in material from " + keys.name(),
                        sources);
            }

            PGPPublicKey k = key.get();
            String fingerprint = hex(k.getFingerprint());
            String uid = firstUserId(k);

            PGPSignature working = signature;
            working.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), k);
            working.update(artifactBytes);
            if (!working.verify()) {
                // Still report the signer: "bytes do not match the signature of key X" is far more
                // actionable for a reviewer than a bare failure.
                return new SignatureVerification(false, pad(keyIdHex), uid, fingerprint,
                        "signature does not match artifact bytes", sources);
            }
            return new SignatureVerification(true, pad(keyIdHex), uid, fingerprint, null, sources);
        } catch (IOException | PGPException | RuntimeException e) {
            return SignatureVerification.failure("verification error: " + e.getMessage(), sources);
        }
    }

    /** Public key metadata, for reporting which key actually signed something. */
    public Optional<KeyInfo> describe(byte[] keyMaterial) {
        try {
            PGPPublicKeyRingCollection rings = readRings(keyMaterial);
            Iterator<PGPPublicKeyRing> it = rings.getKeyRings();
            while (it.hasNext()) {
                PGPPublicKeyRing ring = it.next();
                Iterator<PGPPublicKey> keys = ring.getPublicKeys();
                while (keys.hasNext()) {
                    PGPPublicKey k = keys.next();
                    if (k.isMasterKey()) {
                        return Optional.of(new KeyInfo(
                                pad(Long.toHexString(k.getKeyID()).toUpperCase(Locale.ROOT)),
                                hex(k.getFingerprint()),
                                firstUserId(k)));
                    }
                }
            }
            return Optional.empty();
        } catch (IOException | PGPException e) {
            return Optional.empty();
        }
    }

    /** @param keyId long key id (16 hex) @param fingerprint full fingerprint (40 hex) */
    public record KeyInfo(String keyId, String fingerprint, String userId) { }

    // ------------------------------------------------------------------ internals

    private static PGPSignature firstSignature(byte[] block) throws IOException, PGPException {
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(block))) {
            JcaPGPObjectFactory factory = new JcaPGPObjectFactory(in);
            Object o = factory.nextObject();
            if (o instanceof PGPSignatureList list) {
                return list.isEmpty() ? null : list.get(0);
            }
            if (o instanceof PGPSignature sig) {
                return sig;
            }
            // A signed message rather than a detached signature: take its embedded signature.
            if (o instanceof org.bouncycastle.openpgp.PGPCompressedData) {
                JcaPGPObjectFactory inner =
                        new JcaPGPObjectFactory(((org.bouncycastle.openpgp.PGPCompressedData) o)
                                .getDataStream());
                Object o2 = inner.nextObject();
                if (o2 instanceof PGPSignature sig) {
                    return sig;
                }
            }
            return null;
        }
    }

    private static Optional<PGPPublicKey> findKey(byte[] keyMaterial, long keyId)
            throws IOException, PGPException {
        PGPPublicKeyRingCollection rings = readRings(keyMaterial);
        PGPPublicKey direct = rings.getPublicKey(keyId);
        if (direct != null) {
            return Optional.of(direct);
        }
        // Fall back to scanning: some keys' signing subkeys are not directly addressable.
        Iterator<PGPPublicKeyRing> it = rings.getKeyRings();
        while (it.hasNext()) {
            Iterator<PGPPublicKey> keys = it.next().getPublicKeys();
            while (keys.hasNext()) {
                PGPPublicKey k = keys.next();
                if (k.getKeyID() == keyId) {
                    return Optional.of(k);
                }
            }
        }
        return Optional.empty();
    }

    private static PGPPublicKeyRingCollection readRings(byte[] keyMaterial)
            throws IOException, PGPException {
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(keyMaterial))) {
            return new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
        }
    }

    private static String firstUserId(PGPPublicKey key) {
        Iterator<String> uids = key.getUserIDs();
        return uids.hasNext() ? uids.next() : null;
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /** Left-pad a key id to 16 hex chars so short ids compare equal across sources. */
    private static String pad(String hex) {
        String h = hex.toUpperCase(Locale.ROOT);
        return h.length() >= 16 ? h : "0".repeat(16 - h.length()) + h;
    }

    /**
     * True when a trusted key id (full fingerprint or long id, as written in the metadata file)
     * designates the same key as {@code fingerprint}/{@code keyId}.
     */
    public static boolean keyMatches(String trustedId, String fingerprint, String keyId) {
        if (trustedId == null) {
            return false;
        }
        String t = trustedId.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
        if (fingerprint != null && t.equals(fingerprint.toUpperCase(Locale.ROOT))) {
            return true;
        }
        if (keyId == null) {
            return false;
        }
        String k = keyId.toUpperCase(Locale.ROOT);
        if (t.length() > 16) {
            // A full fingerprint in the file: compare its trailing long id.
            return t.endsWith(k);
        }
        return t.equals(k);
    }
}
