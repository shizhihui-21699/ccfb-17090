package com.example.depreview.config;

import java.net.URI;
import java.nio.file.Path;

public record RepositoryConfig(
        String id,
        URI baseUrl,
        boolean publicRepository,
        boolean internal,
        String usernameEnv,
        String passwordEnv) {

    public RepositoryConfig {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("repository id is required");
        }
        if (baseUrl == null) {
            throw new IllegalArgumentException("repository baseUrl is required");
        }
        String url = baseUrl.toString();
        if (url.startsWith("file:") && !url.startsWith("file:/")) {
            String relativePath = url.substring("file:".length());
            baseUrl = Path.of(relativePath).toAbsolutePath().toUri();
            url = baseUrl.toString();
        }
        if (!url.endsWith("/")) {
            baseUrl = URI.create(url + "/");
        }
    }

    public boolean fileRepository() {
        return "file".equalsIgnoreCase(baseUrl.getScheme());
    }
}
