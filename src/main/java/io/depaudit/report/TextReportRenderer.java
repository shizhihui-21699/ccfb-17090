package io.depaudit.report;

import io.depaudit.diff.MetadataChange;
import io.depaudit.verify.Verdict;
import io.depaudit.verify.VerificationResult;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Renders an {@link AuditResult} for a human reviewer in a pull request.
 *
 * <h2>Why the output is shaped like this</h2>
 *
 * <p>The failure mode the tool exists to prevent is <em>reviewer blindness</em>: the metadata file
 * is thousands of lines long, so nobody reads its diff, and a single tampered entry passes. A report
 * that lists every changed line reproduces that failure. The output therefore leads with the small
 * number of things that actually need a decision:
 *
 * <ol>
 *   <li>contradictions against an authority — these are the attack signature;</li>
 *   <li>trust-widening edits (unscoped keys, also-trust values, disabled verification);</li>
 *   <li>same-version hash edits — a released artifact's bytes do not change;</li>
 *   <li>changes that could not be confirmed, with the reason;</li>
 *   <li>and only then, collapsed, the routine churn.</li>
 * </ol>
 *
 * <p>Every concrete finding carries {@code path:line} so a reviewer can jump straight to it in the
 * diff view instead of scrolling.
 */
public final class TextReportRenderer {

    private static final String RESET = "\u001B[0m";
    private static final String RED = "\u001B[31m";
    private static final String YELLOW = "\u001B[33m";
    private static final String GREEN = "\u001B[32m";
    private static final String BOLD = "\u001B[1m";
    private static final String DIM = "\u001B[2m";

    private final boolean color;
    private final String newPath;

    public TextReportRenderer(boolean color) {
        this(color, null);
    }

    public TextReportRenderer(boolean color, String newPath) {
        this.color = color;
        this.newPath = newPath;
    }

    public void render(AuditResult result, PrintStream out) {
        String newPathLabel = newPath == null ? result.newSource() : newPath;
        header(result, out);

        // ---- 1. What must stop the merge -------------------------------------------------
        List<VerificationResult> contradictions = result.contradictions();
        List<AuditResult.UpgradeSummary> upgradeContradictions = result.upgradeSummaries()
                .stream().filter(u -> u.verdict() == Verdict.CONTRADICTED).toList();

        if (!contradictions.isEmpty() || !upgradeContradictions.isEmpty()) {
            out.println();
            section(out, "BLOCKING: values contradict an authoritative source", RED);
            for (VerificationResult r : contradictions) {
                MetadataChange c = r.change();
                out.println("  " + paint("✗", RED) + " " + bold(c.subject()));
                out.println("    " + location(newPathLabel, c.newLine())
                        + "  " + describe(c));
                for (String e : r.evidence()) {
                    out.println("      " + dim("· " + e));
                }
                out.println("      " + dim("verify at: " + newPathLabel + ":" + c.newLine()));
            }
            for (AuditResult.UpgradeSummary u : upgradeContradictions) {
                out.println("  " + paint("✗", RED) + " " + bold(u.description()));
                out.println("    " + location(newPathLabel, u.newLine()));
                for (String e : u.evidence()) {
                    out.println("      " + dim("· " + e));
                }
            }
        }

        // ---- 2. Trust-widening edits ------------------------------------------------------
        List<MetadataChange> trustEdits = result.blockers().stream()
                .filter(c -> !contradictions.stream().anyMatch(r -> r.change() == c))
                .toList();
        if (!trustEdits.isEmpty()) {
            out.println();
            section(out, "BLOCKING: trust widened or verification weakened", RED);
            for (MetadataChange c : trustEdits) {
                out.println("  " + paint("✗", RED) + " " + bold(c.subject())
                        + "  " + dim("[" + c.category() + "]"));
                out.println("    " + location(newPathLabel, c.newLine()));
                out.println("      " + describe(c));
            }
        }

        // ---- 3. Unconfirmed changes that need a human --------------------------------------
        List<VerificationResult> attention = result.needsHumanAttention().stream()
                .filter(r -> !r.isContradiction())
                .toList();
        if (!attention.isEmpty()) {
            out.println();
            section(out, "REVIEW: changes that could not be confirmed", YELLOW);
            for (VerificationResult r : attention) {
                MetadataChange c = r.change();
                String mark = r.verdict() == Verdict.INTERNAL_ONLY ? "◐" : "?";
                out.println("  " + paint(mark, YELLOW) + " " + c.subject()
                        + "  " + dim("[" + verdictLabel(r.verdict()) + "]"));
                out.println("    " + location(newPathLabel, c.newLine()) + "  " + describe(c));
                for (String e : r.evidence()) {
                    out.println("      " + dim("· " + e));
                }
            }
        }

        // ---- 4. Upgrades that need attention ------------------------------------------------
        // Contradictions are excluded: they are already printed in the blocking section above, and
        // repeating them would make one problem look like two.
        List<AuditResult.UpgradeSummary> upgradeAttention = result.upgradeSummaries().stream()
                .filter(u -> u.verdict() != Verdict.CONFIRMED_CANONICAL
                        && u.verdict() != Verdict.CONFIRMED_MIRROR
                        && u.verdict() != Verdict.NOT_APPLICABLE
                        && u.verdict() != Verdict.CONTRADICTED)
                .toList();
        if (!upgradeAttention.isEmpty()) {
            out.println();
            section(out, "REVIEW: upgrades not confirmed against a canonical repository", YELLOW);
            for (AuditResult.UpgradeSummary u : upgradeAttention) {
                out.println("  " + paint("?", YELLOW) + " " + u.description()
                        + "  " + dim("[" + verdictLabel(u.verdict()) + ", " + u.fileCount()
                        + " file(s)]"));
                out.println("    " + location(newPathLabel, u.newLine()));
                for (String e : u.evidence()) {
                    out.println("      " + dim("· " + e));
                }
            }
        }

        // ---- 5. Changes confirmed by signature rather than by a repository -------------------
        // Worth its own section: "confirmed" is only reassuring if the reviewer can see that the
        // confirmation came from a key they trust, not from a checksum nobody checked.
        List<VerificationResult> signatureConfirmed = result.changeVerdicts().stream()
                .filter(r -> r.verdict() == Verdict.CONFIRMED_BY_SIGNATURE)
                .toList();
        if (!signatureConfirmed.isEmpty()) {
            out.println();
            section(out, "OK: confirmed by signature against a trusted key", GREEN);
            for (VerificationResult r : signatureConfirmed) {
                out.println("  " + paint("✓", GREEN) + " " + r.change().subject());
                out.println("    " + location(newPathLabel, r.change().newLine()));
                for (String e : r.evidence()) {
                    if (e.contains("signature by")) {
                        out.println("      " + dim("· " + e));
                    }
                }
            }
        }

        // ---- 6. Routine churn, summarised --------------------------------------------------
        long routine = result.upgradeSummaries().stream()
                .filter(u -> u.verdict() == Verdict.CONFIRMED_CANONICAL).count();
        if (routine > 0) {
            out.println();
            section(out, "OK: routine upgrades confirmed upstream", GREEN);
            out.println("  " + paint("✓", GREEN) + " " + routine
                    + " version bump(s) whose new digests match a canonical repository.");
            for (AuditResult.UpgradeSummary u : result.upgradeSummaries()) {
                if (u.verdict() == Verdict.CONFIRMED_CANONICAL) {
                    out.println("    " + dim("· " + u.description()));
                }
            }
        }
        long mirrorConfirmed = result.upgradeSummaries().stream()
                .filter(u -> u.verdict() == Verdict.CONFIRMED_MIRROR).count();
        if (mirrorConfirmed > 0) {
            out.println("  " + paint("·", DIM) + " " + mirrorConfirmed
                    + " upgrade(s) matched only a mirror, which is expected for redistributed "
                    + "artifacts.");
            for (AuditResult.UpgradeSummary u : result.upgradeSummaries()) {
                if (u.verdict() == Verdict.CONFIRMED_MIRROR) {
                    out.println("    " + dim("· " + u.description()));
                }
            }
        }

        footer(result, out);
    }

    // ------------------------------------------------------------------ sections

    private void header(AuditResult r, PrintStream out) {
        out.println();
        out.println(paint("═".repeat(72), DIM));
        out.println(paint(" Dependency verification metadata review", BOLD));
        out.println(paint("═".repeat(72), DIM));
        out.println("  " + dim("old: ") + r.oldSource());
        out.println("  " + dim("new: ") + r.newSource());
        out.println("  " + dim("mode: ") + (r.offline() ? "offline (no repositories consulted)"
                : "online"));
        out.println("  " + dim("changes: ") + r.diff().changes().size()
                + "   " + dim("upgrades: ") + r.diff().upgrades().size()
                + (r.diff().upgrades().isEmpty() ? ""
                        : "  (" + r.diff().upgrades().size() + " version bump(s) correlated, "
                                + "not reported as individual deletions/insertions)"));
    }

    private void footer(AuditResult r, PrintStream out) {
        out.println();
        out.println(paint("─".repeat(72), DIM));
        long unconfirmedUpgrades = r.upgradeSummaries().stream()
                .filter(u -> u.verdict() == Verdict.INCONCLUSIVE
                        || u.verdict() == Verdict.INTERNAL_ONLY)
                .count();
        if (r.isBlocking()) {
            out.println("  " + paint("RESULT: BLOCK — do not merge until the items above are resolved.",
                    RED + BOLD));
        } else if (!r.unresolved().isEmpty() || !r.needsHumanAttention().isEmpty()
                || unconfirmedUpgrades > 0) {
            // "PASS" must mean every change was positively accounted for. An unconfirmed upgrade
            // is a review item, not a pass — saying otherwise would be the false assurance this
            // tool exists to prevent.
            out.println("  " + paint("RESULT: REVIEW — nothing contradicts a source, but "
                    + "some changes need a human decision.", YELLOW));
        } else {
            out.println("  " + paint("RESULT: PASS — all changes match authoritative sources.",
                    GREEN));
        }
        if (!r.upgradeVerdicts().isEmpty()) {
            out.println("  " + dim("strongest confirming tier: " + r.bestTier().name()));
        }
        out.println(paint("─".repeat(72), DIM));
        out.println();
    }

    private void section(PrintStream out, String title, String color) {
        out.println(paint("── " + title + " ", color)
                + paint("─".repeat(Math.max(0, 72 - title.length() - 4)), DIM));
    }

    // ------------------------------------------------------------------ formatting

    private static String describe(MetadataChange c) {
        if (c.detail() instanceof MetadataChange.Detail.DigestChange d) {
            if (d.oldValue() == null) {
                return d.algorithm() + " added: " + shorten(d.newValue())
                        + (d.newAlsoTrust() ? "  (also-trust: accepted in addition to the primary "
                                + "hash)" : "");
            }
            if (d.newValue() == null) {
                return d.algorithm() + " removed (was " + shorten(d.oldValue()) + ")";
            }
            return d.algorithm() + " " + shorten(d.oldValue()) + " → " + shorten(d.newValue());
        }
        if (c.detail() instanceof MetadataChange.Detail.PgpKeysChange p) {
            StringBuilder sb = new StringBuilder();
            if (!p.added().isEmpty()) {
                sb.append("signing key(s) added: ").append(String.join(", ", p.added()));
            }
            if (!p.removed().isEmpty()) {
                sb.append(sb.isEmpty() ? "" : "; ").append("removed: ")
                        .append(String.join(", ", p.removed()));
            }
            return sb.toString();
        }
        if (c.detail() instanceof MetadataChange.Detail.TrustedKeyChange t) {
            if (t.oldId() == null) {
                return "trusted key " + t.newId() + " added, scope: " + t.newScope()
                        + (t.keyMaterialAdded() ? "  (key material embedded in the file)" : "");
            }
            return "trusted key " + t.oldId() + ": scope " + t.oldScope()
                    + " → " + t.newScope()
                    + (t.keyMaterialAdded() ? "  (key material embedded in the file)" : "");
        }
        if (c.detail() instanceof MetadataChange.Detail.ToggleChange t) {
            return t.name() + " " + t.oldValue() + " → " + t.newValue();
        }
        if (c.detail() instanceof MetadataChange.Detail.ComponentLifecycle l) {
            return l.note();
        }
        if (c.detail() instanceof MetadataChange.Detail.Unmodelled u) {
            return u.description();
        }
        return "";
    }

    private static String verdictLabel(Verdict v) {
        return switch (v) {
            case CONFIRMED_CANONICAL -> "confirmed upstream";
            case CONFIRMED_MIRROR -> "confirmed by mirror only";
            case INTERNAL_ONLY -> "internal repository only";
            case CONFIRMED_BY_SIGNATURE -> "signature confirmed";
            case CONTRADICTED -> "CONTRADICTED";
            case INCONCLUSIVE -> "unconfirmed";
            case NOT_APPLICABLE -> "n/a";
        };
    }

    private String location(String path, int line) {
        if (line <= 0) {
            return dim("(no line)");
        }
        return paint(path + ":" + line, BOLD);
    }

    private static String shorten(String hex) {
        if (hex == null) {
            return "—";
        }
        return hex.length() <= 20 ? hex : hex.substring(0, 16) + "…" + hex.substring(hex.length() - 4);
    }

    private String paint(String s, String code) {
        return color ? code + s + RESET : s;
    }

    private String bold(String s) {
        return paint(s, BOLD);
    }

    private String dim(String s) {
        return paint(s, DIM);
    }

    /** Machine-readable one-line-per-item summary, for CI logs and annotations. */
    public static List<String> annotationLines(AuditResult r) {
        List<String> out = new ArrayList<>();
        for (VerificationResult vr : r.changeVerdicts()) {
            MetadataChange c = vr.change();
            if (vr.verdict() == Verdict.NOT_APPLICABLE) {
                continue;
            }
            if (c.severity() == MetadataChange.Severity.INFO && !vr.isContradiction()) {
                continue;
            }
            out.add(String.format(Locale.ROOT, "%d:%s\t%s", c.newLine(), c.subject(),
                    verdictLabel(vr.verdict())));
        }
        return out;
    }
}
