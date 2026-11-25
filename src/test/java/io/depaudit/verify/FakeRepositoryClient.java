package io.depaudit.verify;

import io.depaudit.model.ArtifactRef;
import io.depaudit.model.HashAlgorithm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory {@link RepositoryClient} for tests.
 *
 * <p>Records what was asked so tests can assert the verifier never consults a repository it was not
 * configured with, and can simulate network failure per repository.
 */
final class FakeRepositoryClient implements RepositoryClient {

    /** key = repoId|group:name:version|fileName|algorithm */
    private final Map<String, String> checksums = new HashMap<>();
    private final Map<String, byte[]> artifacts = new HashMap<>();
    private final Map<String, byte[]> signatures = new HashMap<>();
    private final Map<String, IOException> failures = new HashMap<>();
    private final java.util.List<String> calls = new java.util.ArrayList<>();

    FakeRepositoryClient put(String repoId, String gav, String fileName, HashAlgorithm alg,
                             String value) {
        checksums.put(key(repoId, gav, fileName, alg.xmlName()), value);
        return this;
    }

    FakeRepositoryClient putArtifact(String repoId, String gav, String fileName, byte[] bytes) {
        artifacts.put(repoId + "|" + gav + "|" + fileName, bytes);
        return this;
    }

    FakeRepositoryClient putSignature(String repoId, String gav, String fileName, byte[] bytes) {
        signatures.put(repoId + "|" + gav + "|" + fileName, bytes);
        return this;
    }

    /** Make every call to {@code repoId} throw. */
    FakeRepositoryClient fail(String repoId, IOException e) {
        failures.put(repoId, e);
        return this;
    }

    java.util.List<String> calls() {
        return java.util.List.copyOf(calls);
    }

    private static String key(String repoId, String gav, String fileName, String alg) {
        return repoId + "|" + gav + "|" + fileName + "|" + alg;
    }

    @Override
    public Optional<String> publishedChecksum(RepositoryConfig repo, ArtifactRef coords,
                                              String fileName, HashAlgorithm algorithm)
            throws IOException {
        calls.add("checksum " + repo.id() + " " + coords.gav() + " " + fileName + " "
                + algorithm.xmlName());
        IOException boom = failures.get(repo.id());
        if (boom != null) {
            throw boom;
        }
        return Optional.ofNullable(
                checksums.get(key(repo.id(), coords.gav(), fileName, algorithm.xmlName())));
    }

    @Override
    public Optional<InputStream> openArtifact(RepositoryConfig repo, ArtifactRef coords,
                                              String fileName) throws IOException {
        calls.add("artifact " + repo.id() + " " + coords.gav() + " " + fileName);
        IOException boom = failures.get(repo.id());
        if (boom != null) {
            throw boom;
        }
        byte[] bytes = artifacts.get(repo.id() + "|" + coords.gav() + "|" + fileName);
        return bytes == null ? Optional.empty() : Optional.of(new ByteArrayInputStream(bytes));
    }

    @Override
    public Optional<byte[]> signature(RepositoryConfig repo, ArtifactRef coords, String fileName)
            throws IOException {
        calls.add("signature " + repo.id() + " " + coords.gav() + " " + fileName);
        IOException boom = failures.get(repo.id());
        if (boom != null) {
            throw boom;
        }
        return Optional.ofNullable(signatures.get(repo.id() + "|" + coords.gav() + "|" + fileName));
    }
}
