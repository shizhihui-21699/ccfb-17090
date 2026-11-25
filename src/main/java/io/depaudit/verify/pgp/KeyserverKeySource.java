package io.depaudit.verify.pgp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

/**
 * Best-effort key retrieval from an HKP / VKS keyserver.
 *
 * <p><b>A key fetched here proves almost nothing on its own.</b> Keyservers are unauthenticated:
 * anyone can publish a key with any user id, and a signature block ships with the key id it wants
 * you to fetch. So "signature verifies against a keyserver-fetched key" means only that the two are
 * internally consistent. It is still useful evidence — a forger would have to control the keyserver
 * entry as well as the artifact — but the verification layer must record where the key came from and
 * never treat this source as equal to a pinned keyring.
 */
public final class KeyserverKeySource implements KeySource {

    /** Well-known, currently-operating keyservers. Order is preference order. */
    public static final String OPENPGP_ORG = "keys.openpgp.org";
    public static final String UBUNTU = "keyserver.ubuntu.com";

    private final String host;
    private final HttpClient http;
    private final Duration timeout;

    public KeyserverKeySource(String host) {
        this(host, Duration.ofSeconds(15));
    }

    public KeyserverKeySource(String host, Duration timeout) {
        this.host = host;
        this.timeout = timeout;
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public String name() {
        return "keyserver:" + host;
    }

    @Override
    public Optional<byte[]> fetch(String keyIdHex) throws IOException {
        if (keyIdHex == null || keyIdHex.isBlank()) {
            return Optional.empty();
        }
        String id = keyIdHex.replaceAll("\\s+", "").toUpperCase(Locale.ROOT);
        // VKS (keys.openpgp.org) takes a full fingerprint; HKP (ubuntu) takes 0x-prefixed ids and
        // also resolves a full fingerprint. Try both shapes so either server can answer.
        String[] urls = {
                "https://" + host + "/vks/v1/by-fingerprint/" + id,
                "https://" + host + "/pks/lookup?op=get&search=0x" + id,
        };
        for (String url : urls) {
            Optional<byte[]> body = get(url, id);
            if (body.isPresent() && looksLikeKey(body.get())) {
                return body;
            }
        }
        return Optional.empty();
    }

    private Optional<byte[]> get(String url, String id) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "depaudit/0.1 (dependency metadata review)")
                .GET()
                .build();
        try {
            HttpResponse<byte[]> resp = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            if (resp.statusCode() == 200 && resp.body() != null && resp.body().length > 0) {
                return Optional.of(update(resp.body()));
            }
            return Optional.empty();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted fetching key " + id + " from " + host, e);
        } catch (java.net.ConnectException | java.net.UnknownHostException e) {
            throw new IOException("Cannot reach keyserver " + host + ": " + e.getMessage(), e);
        }
    }

    private static byte[] update(byte[] body) {
        return body;
    }

    /** A fetched "key" is only useful if it is actually an armored or binary key block. */
    private static boolean looksLikeKey(byte[] body) {
        String head = new String(body, 0, Math.min(body.length, 64),
                java.nio.charset.StandardCharsets.US_ASCII);
        return head.contains("BEGIN PGP PUBLIC KEY BLOCK") || (body.length > 0 && (body[0] & 0x80) != 0);
    }
}
