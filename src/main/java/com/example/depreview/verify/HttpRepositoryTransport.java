package com.example.depreview.verify;

import com.example.depreview.config.RepositoryConfig;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

final class HttpRepositoryTransport implements RepositoryTransport {

    private final RepositoryConfig config;
    private final HttpClient httpClient;

    HttpRepositoryTransport(RepositoryConfig config, int timeoutSeconds) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(Math.max(2, timeoutSeconds)))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    @Override
    public String id() {
        return config.id();
    }

    @Override
    public Optional<String> getString(String relativePath) throws IOException, InterruptedException {
        HttpRequest request = requestBuilder(relativePath).GET().build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() == 404) {
            return Optional.empty();
        }
        if (response.statusCode() / 100 != 2) {
            throw new IOException("Repository " + config.id() + " returned HTTP "
                    + response.statusCode() + " for " + relativePath);
        }
        return Optional.of(response.body());
    }

    @Override
    public Optional<Path> download(String relativePath, Path targetDirectory)
            throws IOException, InterruptedException {
        Files.createDirectories(targetDirectory);
        String fileName = relativePath.substring(relativePath.lastIndexOf('/') + 1);
        Path target = targetDirectory.resolve(fileName);
        HttpRequest request = requestBuilder(relativePath).GET().build();
        HttpResponse<Path> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofFile(target));
        if (response.statusCode() == 404) {
            Files.deleteIfExists(target);
            return Optional.empty();
        }
        if (response.statusCode() / 100 != 2) {
            Files.deleteIfExists(target);
            throw new IOException("Repository " + config.id() + " returned HTTP "
                    + response.statusCode() + " for " + relativePath);
        }
        return Optional.of(target);
    }

    private HttpRequest.Builder requestBuilder(String relativePath) {
        URI uri = config.baseUrl().resolve(relativePath);
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(20))
                .header("Accept", "*/*")
                .header("User-Agent", "dependency-metadata-review/0.1");
        String user = env(config.usernameEnv());
        String password = env(config.passwordEnv());
        if (user != null && password != null) {
            String token = Base64.getEncoder().encodeToString((user + ":" + password).getBytes(StandardCharsets.UTF_8));
            builder.header("Authorization", "Basic " + token);
        }
        return builder;
    }

    private static String env(String name) {
        if (name == null || name.isBlank()) {
            return null;
        }
        return System.getenv(name);
    }
}
