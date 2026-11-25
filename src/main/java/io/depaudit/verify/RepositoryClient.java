package io.depaudit.verify;

import io.depaudit.model.ArtifactRef;
import io.depaudit.model.HashAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

/**
 * Minimal abstraction over "ask a repository for an artifact and its published digests".
 *
 * <p>Kept as an interface so the verification logic can be exercised in tests against recorded
 * fixtures without any network, and so an organisation can plug in a Nexus/Artifactory client
 * without changing the decision logic.
 */
public interface RepositoryClient {

    /**
     * The checksum the repository publishes next to a file, in the ecosystem's sidecar format
     * ({@code <file>.sha256} containing bare hex).
     *
     * @return the hex value, or empty when the repository has no such file
     */
    Optional<String> publishedChecksum(RepositoryConfig repo, ArtifactRef coords,
                                       String fileName, HashAlgorithm algorithm) throws IOException;

    /** Streams the artifact bytes. The caller hashes them and must close the stream. */
    Optional<InputStream> openArtifact(RepositoryConfig repo, ArtifactRef coords,
                                       String fileName) throws IOException;

    /** Signature (`<file>.asc`) for an artifact, if the repository publishes one. */
    Optional<byte[]> signature(RepositoryConfig repo, ArtifactRef coords,
                               String fileName) throws IOException;
}
