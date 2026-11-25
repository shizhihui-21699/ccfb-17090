package io.depaudit.verify.pgp;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * A {@link KeySource} over a keyring file the organisation controls.
 *
 * <p>This is the only key source whose answers can be treated as authoritative, and the design
 * reflects that: key material is loaded once from disk, never fetched, and never modified. A
 * keyserver source, by contrast, is best-effort — see {@link KeyserverKeySource}.
 */
public final class KeyringKeySource implements KeySource {

    private final String label;
    private final Map<String, byte[]> byKeyId = new HashMap<>();
    private final Map<String, byte[]> byFingerprint = new HashMap<>();

    private KeyringKeySource(String label) {
        this.label = label;
    }

    /**
     * Loads a keyring (binary {@code .gpg}/{@code .pgp} or armored {@code .asc}). Multiple keys in
     * one file are supported; each is indexed by its long key id and full fingerprint.
     */
    public static KeyringKeySource load(Path file) throws IOException {
        byte[] raw = Files.readAllBytes(file);
        KeyringKeySource source = new KeyringKeySource("keyring:" + file.getFileName());
        try (InputStream in = PGPUtil.getDecoderStream(new java.io.ByteArrayInputStream(raw))) {
            PGPPublicKeyRingCollection rings =
                    new PGPPublicKeyRingCollection(in, new JcaKeyFingerprintCalculator());
            Iterator<PGPPublicKeyRing> it = rings.getKeyRings();
            while (it.hasNext()) {
                PGPPublicKeyRing ring = it.next();
                byte[] ringBytes = encodeRing(ring);
                Iterator<PGPPublicKey> keys = ring.getPublicKeys();
                while (keys.hasNext()) {
                    PGPPublicKey k = keys.next();
                    String keyId = pad(Long.toHexString(k.getKeyID()).toUpperCase(Locale.ROOT));
                    String fp = hex(k.getFingerprint());
                    source.byKeyId.put(keyId, ringBytes);
                    source.byFingerprint.put(fp, ringBytes);
                }
            }
        } catch (org.bouncycastle.openpgp.PGPException e) {
            throw new IOException("Not a readable PGP keyring: " + file + ": " + e.getMessage(), e);
        }
        // A keyring that parsed but contains no keys is almost certainly the wrong file. Failing
        // loudly here matters: silently falling through to "no key available" would turn a
        // misconfigured path into a build where signature verification never happens.
        if (source.byKeyId.isEmpty()) {
            throw new IOException("No public keys found in " + file
                    + " — is it really a PGP keyring?");
        }
        return source;
    }

    @Override
    public String name() {
        return label;
    }

    @Override
    public Optional<byte[]> fetch(String keyIdHex) {
        String id = pad(keyIdHex.toUpperCase(Locale.ROOT));
        byte[] byId = byKeyId.get(id);
        if (byId != null) {
            return Optional.of(byId);
        }
        // A caller may pass a full fingerprint rather than a long id.
        return Optional.ofNullable(byFingerprint.get(id));
    }

    public int size() {
        return byKeyId.size();
    }

    private static byte[] encodeRing(PGPPublicKeyRing ring) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ArmoredOutputStream armored = new ArmoredOutputStream(out)) {
            ring.encode(armored);
        }
        return out.toByteArray();
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static String pad(String hex) {
        String h = hex.toUpperCase(Locale.ROOT);
        return h.length() >= 16 ? h : "0".repeat(16 - h.length()) + h;
    }
}
