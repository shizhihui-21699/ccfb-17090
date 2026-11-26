package com.example.depreview.verify;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;

public interface RepositoryTransport {

    String id();

    /** Returns empty for HTTP 404 / a missing file. Other failures are exceptional. */
    Optional<String> getString(String relativePath) throws IOException, InterruptedException;

    /** Downloads a public artifact/signature into targetDirectory without executing it. */
    Optional<Path> download(String relativePath, Path targetDirectory)
            throws IOException, InterruptedException;
}
