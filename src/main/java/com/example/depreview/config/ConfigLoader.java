package com.example.depreview.config;

import com.example.depreview.model.Severity;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public final class ConfigLoader {

    private ConfigLoader() {
    }

    public static ReviewConfig load(Path path) throws IOException {
        if (path == null) {
            return ReviewConfig.defaults();
        }
        Properties props = new Properties();
        try (Reader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            props.load(reader);
        }

        ReviewConfig d = ReviewConfig.defaults();
        boolean online = Boolean.parseBoolean(props.getProperty("online", "true"));
        Gate gate = parseGate(props.getProperty("failOn", "HIGH"));
        ReviewConfig.SignatureMode signatureMode = parseSignatureMode(
                props.getProperty("signature.mode", "CONFIGURED"));
        int timeout = parseInt(props.getProperty("timeoutSeconds"), d.timeoutSeconds());
        int parallelism = parseInt(props.getProperty("parallelism"), d.parallelism());
        boolean downloadMissing = Boolean.parseBoolean(
                props.getProperty("downloadMissingArtifacts", "true"));
        int evidence = parseInt(props.getProperty("maxEvidenceLines"), d.maxEvidenceLines());

        Set<String> internalPrefixes = csv(props.getProperty("internalGroupPrefixes"));
        Set<String> allowedHosts = new LinkedHashSet<>(csv(props.getProperty("allowedSourceHosts")));
        Set<String> fingerprints = upper(csv(props.getProperty("trustedPgpFingerprints")));

        List<RepositoryConfig> repositories = loadRepositories(props);
        if (repositories.isEmpty()) {
            repositories = d.repositories();
        }
        repositories.stream().filter(r -> !r.fileRepository()).forEach(r -> allowedHosts.add(r.baseUrl().getHost()));

        Map<String, ArtifactPolicy> policies = loadPolicies(props);

        return new ReviewConfig(
                repositories,
                internalPrefixes,
                allowedHosts,
                fingerprints,
                policies,
                online,
                signatureMode,
                gate,
                timeout,
                parallelism,
                downloadMissing,
                props.getProperty("gpg.executable", "gpg"),
                props.getProperty("gpg.keyring", ""),
                evidence);
    }

    public static Gate parseGate(String value) {
        try {
            return Gate.valueOf(value.trim().toUpperCase());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid failOn value: " + value
                    + " (expected INFO, LOW, MEDIUM, HIGH, CRITICAL or NONE)");
        }
    }

    public static Severity parseSeverity(String value) {
        return Severity.valueOf(value.trim().toUpperCase());
    }

    private static ReviewConfig.SignatureMode parseSignatureMode(String value) {
        try {
            return ReviewConfig.SignatureMode.valueOf(value.trim().toUpperCase());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid signature.mode: " + value
                    + " (expected NONE, CONFIGURED or ALL)");
        }
    }

    private static List<RepositoryConfig> loadRepositories(Properties props) {
        List<String> ids = csvList(props.getProperty("repositories"));
        List<RepositoryConfig> repositories = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (String id : ids) {
            String prefix = "repo." + id + ".";
            String url = props.getProperty(prefix + "url");
            if (url == null || url.isBlank()) {
                throw new IllegalArgumentException("Repository " + id + " requires " + prefix + "url");
            }
            repositories.add(new RepositoryConfig(
                    id,
                    URI.create(url.trim()),
                    Boolean.parseBoolean(props.getProperty(prefix + "public", "false")),
                    Boolean.parseBoolean(props.getProperty(prefix + "internal", "false")),
                    blankToNull(props.getProperty(prefix + "usernameEnv")),
                    blankToNull(props.getProperty(prefix + "passwordEnv"))));
            seen.add(id);
        }

        boolean centralEnabled = Boolean.parseBoolean(props.getProperty("mavenCentral.enabled", "true"));
        if (centralEnabled && seen.stream().noneMatch(id -> id.equalsIgnoreCase("maven-central"))) {
            String centralUrl = props.getProperty("mavenCentral.url",
                    "https://repo1.maven.org/maven2/");
            repositories.add(0, new RepositoryConfig(
                    "maven-central", URI.create(centralUrl), true, false, null, null));
        } else if (!centralEnabled) {
            repositories.removeIf(r -> r.id().equals("maven-central"));
        }
        return repositories;
    }

    private static Map<String, ArtifactPolicy> loadPolicies(Properties props) {
        Map<String, PolicyBuilder> builders = new LinkedHashMap<>();
        for (String name : props.stringPropertyNames()) {
            if (!name.startsWith("policy.")) {
                continue;
            }
            String rest = name.substring("policy.".length());
            int dot = rest.lastIndexOf('.');
            if (dot <= 0) {
                continue;
            }
            String policyName = rest.substring(0, dot);
            String field = rest.substring(dot + 1);
            PolicyBuilder b = builders.computeIfAbsent(policyName, PolicyBuilder::new);
            b.set(field, props.getProperty(name));
        }

        Map<String, ArtifactPolicy> policies = new LinkedHashMap<>();
        builders.forEach((name, b) -> {
            if (b.coordinate == null || b.coordinate.isBlank()) {
                throw new IllegalArgumentException("policy." + name + ".coordinate is required");
            }
            ArtifactPolicy policy = new ArtifactPolicy(
                    b.coordinate.trim(),
                    b.allowSameVersionHashChange,
                    b.allowRepositorySpecificArtifact,
                    csv(b.allowedRepositories),
                    csv(b.approvedHashes),
                    upper(csv(b.trustedFingerprints)),
                    b.reason == null ? "" : b.reason.trim());
            policies.put(policy.key(), policy);
        });
        return policies;
    }

    private static Set<String> csv(String value) {
        Set<String> out = new LinkedHashSet<>();
        if (value == null || value.isBlank()) {
            return out;
        }
        for (String part : value.split(",")) {
            String p = part.trim();
            if (!p.isEmpty()) {
                out.add(p);
            }
        }
        return out;
    }

    private static List<String> csvList(String value) {
        return new ArrayList<>(csv(value));
    }

    private static Set<String> upper(Set<String> input) {
        Set<String> out = new LinkedHashSet<>();
        input.forEach(v -> out.add(v.toUpperCase()));
        return out;
    }

    private static int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return Integer.parseInt(value.trim());
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static final class PolicyBuilder {
        private final String name;
        private String coordinate;
        private boolean allowSameVersionHashChange;
        private boolean allowRepositorySpecificArtifact;
        private String allowedRepositories = "";
        private String approvedHashes = "";
        private String trustedFingerprints = "";
        private String reason = "";

        private PolicyBuilder(String name) {
            this.name = name;
        }

        private void set(String field, String value) {
            switch (field) {
                case "coordinate" -> coordinate = value;
                case "allowSameVersionHashChange" ->
                        allowSameVersionHashChange = Boolean.parseBoolean(value);
                case "allowRepositorySpecificArtifact" ->
                        allowRepositorySpecificArtifact = Boolean.parseBoolean(value);
                case "allowedRepositories" -> allowedRepositories = value;
                case "approvedHashes" -> approvedHashes = value;
                case "trustedFingerprints" -> trustedFingerprints = value;
                case "reason" -> reason = value;
                default -> {
                    // Ignore forward-compatible policy fields rather than failing an MR.
                }
            }
        }
    }
}
