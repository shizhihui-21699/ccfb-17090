package io.depaudit.verify.pgp;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Supplies public keys by key id.
 *
 * <p>An interface rather than a hard-wired keyserver call because key retrieval is the weakest link
 * in PGP verification, and organisations differ on how they want it handled. A keyserver is
 * <em>unauthenticated</em>: anyone can upload a key claiming any identity, so a key fetched from a
 * keyserver only establishes "the signature is internally consistent with this key", never "this
 * key belongs to the library author". Trust in the key has to come from somewhere else — Gradle's
 * own {@code <trusted-key>} list, a pinned keyring, or a key server the organisation controls.
 */
public interface KeySource {

    /** Human-readable name used in evidence, e.g. {@code keys.openpgp.org}. */
    String name();

    Optional<byte[]> fetch(String keyIdHex) throws IOException;

    /**
     * The "no keys available" source. It is a single shared instance so callers can compare by
     * identity to ask "are signatures enabled at all?" cheaply and correctly, instead of guessing
     * from {@link #name()}.
     */
    KeySource NONE = new KeySource() {
        @Override
        public String name() {
            return "no-key-source";
        }

        @Override
        public Optional<byte[]> fetch(String keyIdHex) {
            return Optional.empty();
        }
    };

    static KeySource none() {
        return NONE;
    }

    static KeySource fixed(String name, byte[] armoredKey) {
        return new KeySource() {
            @Override
            public String name() {
                return name;
            }

            @Override
            public Optional<byte[]> fetch(String keyIdHex) {
                return keyIdHex != null && !keyIdHex.isBlank()
                        ? Optional.of(armoredKey)
                        : Optional.empty();
            }
        };
    }

    static KeySource chain(List<KeySource> sources) {
        List<KeySource> copy = List.copyOf(sources);
        return new KeySource() {
            @Override
            public String name() {
                return copy.stream().map(KeySource::name).reduce((a, b) -> a + "+" + b).orElse("none");
            }

            @Override
            public Optional<byte[]> fetch(String keyIdHex) throws IOException {
                for (KeySource s : copy) {
                    Optional<byte[]> got = s.fetch(keyIdHex);
                    if (got.isPresent()) {
                        return got;
                    }
                }
                return Optional.empty();
            }
        };
    }
}
