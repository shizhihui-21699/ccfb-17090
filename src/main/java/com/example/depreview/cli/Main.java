package com.example.depreview.cli;

import com.example.depreview.analyze.PolicyChangeAnalyzer;
import com.example.depreview.analyze.ReviewEngine;
import com.example.depreview.config.ConfigLoader;
import com.example.depreview.config.Gate;
import com.example.depreview.config.ReviewConfig;
import com.example.depreview.diff.BuildCorrelator;
import com.example.depreview.diff.MetadataDiffer;
import com.example.depreview.diff.UnifiedDiffParser;
import com.example.depreview.gradle.GradleMetadataParser;
import com.example.depreview.model.ArtifactMutation;
import com.example.depreview.model.Finding;
import com.example.depreview.model.ReviewReport;
import com.example.depreview.report.JsonReporter;
import com.example.depreview.report.MarkdownReporter;
import com.example.depreview.verify.VerificationService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Main {

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        try {
            CliArgs cli = CliArgs.parse(args);
            if (cli.help) {
                printHelp();
                return 0;
            }
            if (cli.base == null || cli.head == null) {
                System.err.println("Both --base <old-verification-metadata.xml> and --head <new-file> are required.");
                printHelp();
                return 2;
            }

            ReviewConfig config = cli.config == null
                    ? ReviewConfig.defaults()
                    : ConfigLoader.load(Path.of(cli.config));
            if (cli.offline) {
                config = config.withOnline(false);
            }
            if (cli.failOn != null) {
                config = config.withFailOn(ConfigLoader.parseGate(cli.failOn));
            }

            GradleMetadataParser parser = new GradleMetadataParser();
            GradleMetadataParser.GradleParseResult oldParsed = parser.parse(Path.of(cli.base));
            GradleMetadataParser.GradleParseResult newParsed = parser.parse(Path.of(cli.head));

            MetadataDiffer differ = new MetadataDiffer();
            List<ArtifactMutation> mutations = differ.diff(oldParsed.snapshot(), newParsed.snapshot());

            BuildCorrelator correlator = null;
            if (!cli.buildPatches.isEmpty()) {
                UnifiedDiffParser patchParser = new UnifiedDiffParser();
                List<UnifiedDiffParser.PatchFile> files = new ArrayList<>();
                for (String patchPath : cli.buildPatches) {
                    String content = Files.readString(Path.of(patchPath), StandardCharsets.UTF_8);
                    files.addAll(patchParser.parse(content).files());
                }
                correlator = new BuildCorrelator(new UnifiedDiffParser.Patch(files));
            }

            List<Finding> policyFindings = new ArrayList<>();
            if (cli.metadataPatch != null) {
                String patchContent = Files.readString(Path.of(cli.metadataPatch), StandardCharsets.UTF_8);
                UnifiedDiffParser.Patch metadataPatch = new UnifiedDiffParser().parse(patchContent);
                policyFindings = new PolicyChangeAnalyzer().analyze(metadataPatch);
            }

            // Trust only pins already present in the base revision or explicit policy/config.
            // Trusting newly added <trusted-key> entries would let an attacker endorse their key.
            Set<String> baseTrustedKeys = new LinkedHashSet<>(oldParsed.trustedKeyIds());
            VerificationService verificationService = new VerificationService(config, baseTrustedKeys);
            ReviewEngine engine = new ReviewEngine(config, verificationService, correlator);
            ReviewReport report = engine.review(mutations, policyFindings);

            String output = "json".equalsIgnoreCase(cli.format)
                    ? new JsonReporter().render(report)
                    : new MarkdownReporter().render(report);

            if (cli.output != null) {
                Path outputPath = Path.of(cli.output);
                if (outputPath.getParent() != null) {
                    Files.createDirectories(outputPath.getParent());
                }
                Files.writeString(outputPath, output, StandardCharsets.UTF_8);
            } else {
                System.out.print(output);
            }

            return report.failed() ? 1 : 0;
        } catch (IllegalArgumentException e) {
            System.err.println("Argument/configuration error: " + e.getMessage());
            return 2;
        } catch (IOException e) {
            System.err.println("Review failed: " + e.getMessage());
            return 3;
        } catch (Exception e) {
            System.err.println("Unexpected review failure: " + e);
            e.printStackTrace(System.err);
            return 3;
        }
    }

    private static void printHelp() {
        System.out.println("""
                dependency-metadata-review

                USAGE:
                  dep-review --base <old.xml> --head <new.xml> [options]

                OPTIONS:
                  --base <file>             Base revision verification-metadata.xml
                  --head <file>             Head/MR revision verification-metadata.xml
                  --metadata-patch <file>   Unified diff used to detect trust-policy downgrades
                  --build-patch <file>      Unified diff of build files; may be repeated
                  --config <file.properties>
                  --format <markdown|json>  Output format (default: markdown)
                  --output <file>           Write report to file instead of stdout
                  --fail-on <gate>          INFO, LOW, MEDIUM, HIGH, CRITICAL, NONE
                  --offline                 Skip repository and signature network checks
                  -h, --help                Show help

                EXIT CODES:
                  0  No findings exceed the gate
                  1  Blocking findings
                  2  Bad arguments/configuration
                  3  I/O or verification execution failure
                """);
    }

    private static final class CliArgs {
        private String base;
        private String head;
        private String metadataPatch;
        private String config;
        private String format = "markdown";
        private String output;
        private String failOn;
        private boolean offline;
        private boolean help;
        private final List<String> buildPatches = new ArrayList<>();

        private static CliArgs parse(String[] args) {
            CliArgs cli = new CliArgs();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "-h", "--help" -> cli.help = true;
                    case "--offline" -> cli.offline = true;
                    case "--base" -> cli.base = requireValue(args, ++i, arg);
                    case "--head" -> cli.head = requireValue(args, ++i, arg);
                    case "--metadata-patch", "--patch" -> cli.metadataPatch = requireValue(args, ++i, arg);
                    case "--config" -> cli.config = requireValue(args, ++i, arg);
                    case "--format" -> cli.format = requireValue(args, ++i, arg);
                    case "--output" -> cli.output = requireValue(args, ++i, arg);
                    case "--fail-on" -> cli.failOn = requireValue(args, ++i, arg);
                    case "--build-patch" -> cli.buildPatches.add(requireValue(args, ++i, arg));
                    default -> {
                        if (arg.startsWith("--base=")) cli.base = arg.substring("--base=".length());
                        else if (arg.startsWith("--head=")) cli.head = arg.substring("--head=".length());
                        else if (arg.startsWith("--metadata-patch=")) cli.metadataPatch = arg.substring("--metadata-patch=".length());
                        else if (arg.startsWith("--patch=")) cli.metadataPatch = arg.substring("--patch=".length());
                        else if (arg.startsWith("--config=")) cli.config = arg.substring("--config=".length());
                        else if (arg.startsWith("--format=")) cli.format = arg.substring("--format=".length());
                        else if (arg.startsWith("--output=")) cli.output = arg.substring("--output=".length());
                        else if (arg.startsWith("--fail-on=")) cli.failOn = arg.substring("--fail-on=".length());
                        else throw new IllegalArgumentException("Unknown argument: " + arg);
                    }
                }
                if (arg.startsWith("--") && arg.contains("=")) {
                    // Values were consumed in the default branch; no index adjustment needed.
                }
            }
            return cli;
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Option " + option + " requires a value");
            }
            return args[index];
        }
    }
}
