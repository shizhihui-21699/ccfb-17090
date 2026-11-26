package com.example.depreview.verify;

import com.example.depreview.config.RepositoryConfig;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;

final class FileRepositoryTransport implements RepositoryTransport {

    private final RepositoryConfig config;
    private final Path root;

    FileRepositoryTransport(RepositoryConfig config) {
        this.config = config;
        this.root = Path.of(config.baseUrl());
    }

    @Override
    public String id() {
        return config.id();
    }

    @Override
    public Optional<String> getString(String relativePath) throws IOException {
        Path path = root.resolve(relativePath).normalize();
        if (!path.startsWith(root.normalize()) || !Files.isRegularFile(path)) {
            return Optional.empty();
        }
        return Optional.of(Files.readString(path, StandardCharsets.UTF_8));
    }

    @Override
    public Optional<Path> download(String relativePath, Path targetDirectory) throws IOException {
        Path source = root.resolve(relativePath).normalize();
        if (!source.startsWith(root.normalize()) || !Files.isRegularFile(source)) {
            return Optional.empty();
        }
        Files.createDirectories(targetDirectory);
        Path target = targetDirectory.resolve(source.getFileName().toString());
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        return Optional.of(target);
    }
}
