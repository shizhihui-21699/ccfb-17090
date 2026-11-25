package io.depaudit;

import io.depaudit.parse.MetadataParseException;
import io.depaudit.report.AuditResult;
import io.depaudit.report.JsonReportRenderer;
import io.depaudit.report.TextReportRenderer;
import io.depaudit.verify.HttpRepositoryClient;
import io.depaudit.verify.RepositoryConfig;
import io.depaudit.verify.RepositoryClient;
import io.depaudit.verify.TrustTier;
import io.depaudit.verify.VerificationPolicy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Command-line entry point.
 *
 * <p>Exit codes are the contract with CI: {@code 0} pass, {@code 1} review needed (nothing proven
 * wrong, but a human must decide), {@code 2} blocked, {@code 3} the tool could not complete (bad
 * arguments, unparseable file). Separating 1 from 2 matters: a build that fails on every routine
 * dependency bump gets disabled, and a disabled check catches nothing.
 */
public final class Main {

    public static void main(String[] args) {
        System.exit(run(args));
    }

    static int run(String[] args) {
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println();
            usage(System.err);
            return 3;
        }
        if (opts.help) {
            usage(System.out);
            return 0;
        }

        try {
            VerificationPolicy policy = opts.toPolicy();
            Path oldFile = opts.materialiseOld();
            AuditResult result = new AuditService().audit(oldFile, opts.newFile, policy);

            if (opts.json) {
                new JsonReportRenderer().render(result, System.out);
            } else {
                new TextReportRenderer(opts.color != Boolean.FALSE, opts.newFile.toString())
                        .render(result, System.out);
            }

            if (result.isBlocking()) {
                return 2;
            }
            if (opts.failOnReview
                    && (!result.unresolved().isEmpty()
                        || !result.needsHumanAttention().isEmpty()
                        || result.upgradesNeedingAttention() > 0)) {
                return 1;
            }
            return 0;
        } catch (MetadataParseException e) {
            System.err.println("error: " + e.getMessage());
            return 3;
        } catch (java.io.IOException e) {
            System.err.println("error: " + e.getMessage());
            return 3;
        } catch (RuntimeException e) {
            System.err.println("error: " + e);
            if (opts.verbose) {
                e.printStackTrace(System.err);
            }
            return 3;
        }
    }

    private static void usage(java.io.PrintStream out) {
        out.println("""
                depaudit — review changes to Gradle dependency-verification metadata

                USAGE
                  depaudit --old <previous verification-metadata.xml> --new <current> [options]
                  depaudit --new <current> --base <git-rev> [options]     (reads the old side from git)

                OPTIONS
                  --old <file>            Previous revision of the metadata file.
                  --new <file>            Revision under review. Defaults to
                                          gradle/verification-metadata.xml.
                  --base <rev>            Read the previous revision from git at <rev>.
                  --repo <id>=<url>[@tier[@offline]]
                                          Add a repository to consult. tier is one of
                                          canonical|mirror|internal|untrusted. Repeatable.
                                          Default: maven-central=https://repo1.maven.org/maven2@canonical
                  --keyring <file>        PGP keyring of keys you trust, for signature
                                          verification. Repeatable.
                  --keyserver <host>      Best-effort key lookup (e.g. keys.openpgp.org). A
                                          keyserver is unauthenticated, so its keys are weak
                                          evidence — prefer --keyring.
                  --offline               Parse and diff only; make no network calls.
                  --json                  Machine-readable output for CI.
                  --fail-on-review        Exit 1 when a change needs human judgement.
                  --no-color              Disable ANSI colour.
                  --verbose               Print stack traces on internal errors.
                  -h, --help              Show this help.

                EXIT CODES
                  0  every change is accounted for
                  1  review needed (with --fail-on-review)
                  2  blocked: a value contradicts an authority, or trust was widened
                  3  the tool could not complete
                """);
    }

    /** Parsed command line. Package-private so tests can build one without spawning a process. */
    static final class Options {
        Path oldFile;
        Path newFile = Path.of("gradle", "verification-metadata.xml");
        String baseRev;
        final List<RepositoryConfig> repos = new ArrayList<>();
        final List<Path> keyrings = new ArrayList<>();
        final List<String> keyservers = new ArrayList<>();
        boolean offline;
        boolean json;
        boolean failOnReview;
        Boolean color = Boolean.TRUE;
        boolean verbose;
        boolean help;

        static Options parse(String[] args) {
            Options o = new Options();
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                switch (a) {
                    case "-h", "--help" -> o.help = true;
                    case "--old" -> o.oldFile = Path.of(requireValue(args, ++i, a));
                    case "--new" -> o.newFile = Path.of(requireValue(args, ++i, a));
                    case "--base" -> o.baseRev = requireValue(args, ++i, a);
                    case "--repo" -> o.repos.add(parseRepo(requireValue(args, ++i, a)));
                    case "--keyring" -> o.keyrings.add(Path.of(requireValue(args, ++i, a)));
                    case "--keyserver" -> o.keyservers.add(requireValue(args, ++i, a));
                    case "--offline" -> o.offline = true;
                    case "--json" -> o.json = true;
                    case "--fail-on-review" -> o.failOnReview = true;
                    case "--no-color" -> o.color = Boolean.FALSE;
                    case "--color" -> o.color = Boolean.TRUE;
                    case "--verbose" -> o.verbose = true;
                    default -> throw new IllegalArgumentException("unknown option: " + a);
                }
            }
            if (o.help) {
                return o;
            }
            if (o.oldFile != null && o.baseRev != null) {
                throw new IllegalArgumentException("--old and --base are mutually exclusive");
            }
            if (o.oldFile == null && o.baseRev == null) {
                throw new IllegalArgumentException("one of --old or --base is required");
            }
            return o;
        }

        VerificationPolicy toPolicy() {
            List<RepositoryConfig> use = repos.isEmpty()
                    ? List.of(RepositoryConfig.mavenCentral())
                    : List.copyOf(repos);
            RepositoryClient client = new HttpRepositoryClient();
            return new VerificationPolicy(use, client, offline, buildKeySource());
        }

        /**
         * Builds the key source from pinned keyrings first, then any keyservers. Order matters:
         * a key found in a local keyring must win over the same key fetched from a keyserver, so
         * pinning a key cannot be undermined by a keyserver answering first.
         */
        private io.depaudit.verify.pgp.KeySource buildKeySource() {
            List<io.depaudit.verify.pgp.KeySource> sources = new ArrayList<>();
            for (Path ring : keyrings) {
                try {
                    sources.add(io.depaudit.verify.pgp.KeyringKeySource.load(ring));
                } catch (java.io.IOException e) {
                    throw new IllegalArgumentException("cannot load --keyring " + ring + ": "
                            + e.getMessage(), e);
                }
            }
            for (String host : keyservers) {
                sources.add(new io.depaudit.verify.pgp.KeyserverKeySource(host));
            }
            if (sources.isEmpty()) {
                return io.depaudit.verify.pgp.KeySource.none();
            }
            return sources.size() == 1 ? sources.get(0)
                    : io.depaudit.verify.pgp.KeySource.chain(sources);
        }

        /** Resolves the old revision, materialising it from git when {@code --base} was given. */
        Path materialiseOld() throws java.io.IOException {
            if (oldFile != null) {
                if (!Files.isReadable(oldFile)) {
                    throw new java.io.FileNotFoundException("cannot read --old " + oldFile);
                }
                return oldFile;
            }
            GitBaseReader reader = new GitBaseReader();
            return reader.materialise(baseRev, newFile);
        }

        static RepositoryConfig parseRepo(String spec) {
            // id=url[@tier[@offline]]
            int eq = spec.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException(
                        "--repo expects id=url[@tier], got: " + spec);
            }
            String id = spec.substring(0, eq).trim();
            String rest = spec.substring(eq + 1).trim();
            TrustTier tier = TrustTier.CANONICAL;
            boolean offline = false;
            String[] parts = rest.split("@");
            String url = parts[0];
            for (int i = 1; i < parts.length; i++) {
                String p = parts[i].trim();
                if ("offline".equalsIgnoreCase(p)) {
                    offline = true;
                } else {
                    tier = parseTier(p, spec);
                }
            }
            if (url.isBlank()) {
                throw new IllegalArgumentException("--repo is missing a URL: " + spec);
            }
            return new RepositoryConfig(id, url, tier, offline);
        }

        private static TrustTier parseTier(String s, String spec) {
            return switch (s.toLowerCase(java.util.Locale.ROOT)) {
                case "canonical" -> TrustTier.CANONICAL;
                case "mirror" -> TrustTier.MIRROR;
                case "internal" -> TrustTier.INTERNAL;
                case "untrusted" -> TrustTier.UNTRUSTED;
                default -> throw new IllegalArgumentException(
                        "unknown trust tier '" + s + "' in --repo " + spec
                                + " (expected canonical|mirror|internal|untrusted)");
            };
        }

        private static String requireValue(String[] args, int i, String flag) {
            if (i >= args.length) {
                throw new IllegalArgumentException(flag + " requires a value");
            }
            return args[i];
        }
    }
}
