package com.example.depreview.verify;

import com.example.depreview.config.ReviewConfig;
import com.example.depreview.model.MetadataRecord;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Verifies detached PGP signatures through GnuPG. The tool itself never loads a downloaded
 * archive; GPG only reads the signature and bytes to verify the detached signature.
 */
public final class GpgSignatureVerifier {

    public SignatureCheck verify(
            MetadataRecord record,
            String artifactRelativePath,
            RepositoryTransport transport,
            String repositoryId,
            Path workDirectory,
            Set<String> trustedFingerprints,
            ReviewConfig config) {

        if (config.signatureMode() == ReviewConfig.SignatureMode.NONE) {
            return new SignatureCheck(SignatureCheck.Status.NOT_REQUESTED,
                    firstKey(record), null, null, repositoryId, null,
                    "Signature verification disabled");
        }

        try {
            Optional<Path> signature = transport.download(
                    artifactRelativePath + ".asc", workDirectory.resolve("signatures"));
            if (signature.isEmpty()) {
                return new SignatureCheck(SignatureCheck.Status.NOT_FOUND,
                        firstKey(record), null, null, repositoryId,
                        artifactRelativePath + ".asc", "No .asc signature published");
            }

            Optional<Path> artifact = transport.download(
                    artifactRelativePath, workDirectory.resolve("artifacts"));
            if (artifact.isEmpty()) {
                return new SignatureCheck(SignatureCheck.Status.NOT_FOUND,
                        firstKey(record), null, null, repositoryId,
                        artifactRelativePath, "Artifact unavailable for signature verification");
            }

            Path gnupgHome = workDirectory.resolve("gnupg-home");
            Files.createDirectories(gnupgHome);
            try {
                Files.setPosixFilePermissions(gnupgHome, Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE));
            } catch (UnsupportedOperationException ignored) {
                // Non-POSIX filesystem; GnuPG on Windows can use the directory as-is.
            }

            if (config.gpgKeyring() == null || config.gpgKeyring().isBlank()) {
                fetchKeys(record, config, gnupgHome);
            }

            List<String> command = new ArrayList<>();
            command.add(config.gpgExecutable());
            command.add("--batch");
            command.add("--no-tty");
            command.add("--status-fd");
            command.add("1");
            command.add("--trust-model");
            command.add("always");
            command.add("--homedir");
            command.add(gnupgHome.toString());
            if (config.gpgKeyring() != null && !config.gpgKeyring().isBlank()) {
                command.add("--no-default-keyring");
                command.add("--keyring");
                command.add(config.gpgKeyring());
            }
            command.add("--verify");
            command.add(signature.get().toString());
            command.add(artifact.get().toString());

            ProcessResult result = run(command, gnupgHome, config.timeoutSeconds() * 2L);
            ParsedGpg parsed = parseStatus(result.output());
            String keyId = parsed.fingerprint != null ? parsed.fingerprint : firstKey(record);
            String artifactUrl = artifactRelativePath;

            if (result.timedOut()) {
                return new SignatureCheck(SignatureCheck.Status.ERROR, keyId, parsed.fingerprint,
                        parsed.userId, repositoryId, artifactUrl, "GPG verification timed out");
            }
            if (result.exitCode() != 0 && result.output().contains("BADSIG")) {
                return new SignatureCheck(SignatureCheck.Status.INVALID, keyId, parsed.fingerprint,
                        parsed.userId, repositoryId, artifactUrl, "Bad PGP signature");
            }
            if (parsed.fingerprint == null || (!result.output().contains("VALIDSIG") && result.exitCode() != 0)) {
                boolean missingKey = result.output().contains("NO_PUBKEY");
                return new SignatureCheck(
                        missingKey ? SignatureCheck.Status.NOT_CONFIGURED : SignatureCheck.Status.ERROR,
                        keyId, parsed.fingerprint, parsed.userId, repositoryId, artifactUrl,
                        missingKey ? "Signing public key is not available/trusted"
                                : "PGP verification failed: " + abbreviate(result.output()));
            }

            boolean trusted = isTrusted(parsed.fingerprint, trustedFingerprints, record);
            return new SignatureCheck(
                    trusted ? SignatureCheck.Status.VALID_TRUSTED : SignatureCheck.Status.VALID_UNTRUSTED,
                    keyId, parsed.fingerprint, parsed.userId, repositoryId, artifactUrl,
                    trusted ? "Valid signature from pinned fingerprint"
                            : "Valid signature, but fingerprint is not in the trusted-key policy");
        } catch (Exception e) {
            return new SignatureCheck(SignatureCheck.Status.ERROR, firstKey(record), null, null,
                    repositoryId, artifactRelativePath, abbreviate(e.getClass().getSimpleName() + ": " + e.getMessage()));
        }
    }

    private void fetchKeys(MetadataRecord record, ReviewConfig config, Path gnupgHome) {
        Set<String> keyIds = new HashSet<>();
        record.signers().forEach(s -> keyIds.add(s.keyId()));
        for (String keyId : keyIds) {
            if (keyId == null || keyId.isBlank()) {
                continue;
            }
            try {
                List<String> command = List.of(
                        config.gpgExecutable(), "--batch", "--no-tty",
                        "--homedir", gnupgHome.toString(),
                        "--keyserver", "https://keys.openpgp.org",
                        "--recv-keys", keyId);
                run(command, gnupgHome, config.timeoutSeconds());
            } catch (Exception ignored) {
                // Verification reports the key as unavailable if lookup/import fails.
            }
        }
    }

    private static boolean isTrusted(String fingerprint, Set<String> trusted, MetadataRecord record) {
        String fp = fingerprint.toUpperCase();
        if (trusted.stream().map(String::toUpperCase).anyMatch(fp::equals)) {
            return true;
        }
        // Gradle's <pgp value="..."> is itself a pin. Modern Gradle requires full fingerprints;
        // accept exact matches only, never suffix matching against an unknown short id.
        return record.signers().stream().anyMatch(s -> fp.equalsIgnoreCase(s.keyId()));
    }

    private static String firstKey(MetadataRecord record) {
        return record.signers().isEmpty() ? null : record.signers().get(0).keyId();
    }

    private static ParsedGpg parseStatus(String output) {
        String fingerprint = null;
        String userId = null;
        for (String line : output.split("\\R")) {
            if (line.startsWith("[GNUPG:] VALIDSIG ")) {
                String[] parts = line.split("\\s+");
                if (parts.length >= 3) {
                    fingerprint = parts[2].toUpperCase();
                }
            } else if (line.startsWith("[GNUPG:] GOODSIG ")) {
                int firstQuote = line.indexOf(' ');
                int second = line.indexOf(' ', firstQuote + 1);
                if (second > 0) {
                    userId = line.substring(second + 1).trim();
                }
                if (fingerprint == null) {
                    String[] parts = line.split("\\s+", 4);
                    if (parts.length >= 3) {
                        fingerprint = parts[2].toUpperCase();
                    }
                }
            }
        }
        return new ParsedGpg(fingerprint, userId);
    }

    private ProcessResult run(List<String> command, Path gnupgHome, long timeoutSeconds)
            throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        pb.environment().put("GNUPGHOME", gnupgHome.toAbsolutePath().toString());
        Process process = pb.start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        boolean timedOut = false;
        int exit = -1;
        if (!finished) {
            process.destroyForcibly();
            timedOut = true;
        } else {
            exit = process.exitValue();
        }
        return new ProcessResult(exit, output, timedOut);
    }

    private static String abbreviate(String value) {
        if (value == null) {
            return "";
        }
        String oneLine = value.replaceAll("\\s+", " ").trim();
        return oneLine.length() <= 500 ? oneLine : oneLine.substring(0, 500) + "…";
    }

    private record ParsedGpg(String fingerprint, String userId) {
    }

    private record ProcessResult(int exitCode, String output, boolean timedOut) {
    }
}
