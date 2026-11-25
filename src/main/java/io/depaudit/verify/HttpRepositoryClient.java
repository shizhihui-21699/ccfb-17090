package io.depaudit.verify;

import io.depaudit.model.ArtifactRef;
import io.depaudit.model.HashAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;

/**
 * {@link RepositoryClient} over plain HTTP, the way Maven repositories actually serve files.
 *
 * <p>Note what this class deliberately does <em>not</em> do: follow a redirect to a different host
 * and accept a checksum from there. Maven Central answers some requests with a redirect to a CDN,
 * and a repository under an attacker's control can answer anything with a redirect elsewhere, so
 * every cross-host redirect is refused and the result is "not found". A checksum obtained from
 * somewhere other than the configured repository proves nothing about that repository.
 */
public final class HttpRepositoryClient implements RepositoryClient {

    private final HttpClient http;
    private final Duration timeout;

    public HttpRepositoryClient() {
        this(Duration.ofSeconds(20));
    }

    public HttpRepositoryClient(Duration timeout) {
        this.timeout = timeout;
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(timeout)
                .build();
    }

    @Override
    public Optional<String> publishedChecksum(RepositoryConfig repo, ArtifactRef coords,
                                              String fileName, HashAlgorithm algorithm)
            throws IOException {
        String url = repo.urlFor(dir(coords), fileName) + "." + algorithm.xmlName();
        HttpResponse<String> resp = send(url);
        if (resp.statusCode() != 200) {
            return Optional.empty();
        }
        String body = resp.body() == null ? "" : resp.body().trim();
        // The sidecar may be "<hex>" or "<hex>  <filename>".
        String hex = body.split("\\s+", 2)[0].toLowerCase(Locale.ROOT);
        if (!algorithm.looksWellFormed(hex)) {
            return Optional.empty();
        }
        return Optional.of(hex);
    }

    @Override
    public Optional<InputStream> openArtifact(RepositoryConfig repo, ArtifactRef coords,
                                              String fileName) throws IOException {
        String url = repo.urlFor(dir(coords), fileName);
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .GET()
                .build();
        try {
            HttpResponse<InputStream> resp = http.send(req, HttpResponse.BodyHandlers.ofInputStream());
            if (resp.statusCode() != 200) {
                resp.body().close();
                return Optional.empty();
            }
            return Optional.of(resp.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted fetching " + url, e);
        }
    }

    @Override
    public Optional<byte[]> signature(RepositoryConfig repo, ArtifactRef coords,
                                      String fileName) throws IOException {
        String url = repo.urlFor(dir(coords), fileName) + ".asc";
        HttpResponse<byte[]> resp = sendBytes(url);
        if (resp.statusCode() != 200) {
            return Optional.empty();
        }
        return Optional.of(resp.body());
    }

    private HttpResponse<String> send(String url) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "depaudit/0.1 (dependency metadata review)")
                .GET()
                .build();
        try {
            return http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted fetching " + url, e);
        }
    }

    private HttpResponse<byte[]> sendBytes(String url) throws IOException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("User-Agent", "depaudit/0.1 (dependency metadata review)")
                .GET()
                .build();
        try {
            return http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted fetching " + url, e);
        }
    }

    private static String dir(ArtifactRef coords) {
        return coords.group().replace('.', '/') + "/" + coords.name() + "/"
                + (coords.version() == null ? "" : coords.version());
    }
}
