package com.example.depreview.diff;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UnifiedDiffParser {

    private static final Pattern HUNK =
            Pattern.compile("^@@ -(\\d+)(?:,(\\d+))? \\+(\\d+)(?:,(\\d+))? @@.*$");

    public Patch parse(String content) {
        List<String> lines = content == null ? List.of() : List.of(content.split("\\R", -1));
        List<PatchFile> files = new ArrayList<>();
        PatchFile.Builder current = null;
        List<DiffLine> hunkLines = null;
        int oldLine = 0;
        int newLine = 0;

        for (String raw : lines) {
            if (raw.startsWith("diff --git ")) {
                if (current != null) {
                    current.addHunk(buildHunk(hunkStartOld, hunkOldCount, hunkStartNew, hunkNewCount, hunkLines));
                    files.add(current.build());
                }
                current = PatchFile.builder();
                hunkLines = null;
                continue;
            }
            if (current == null) {
                if (raw.startsWith("--- ")) {
                    current = PatchFile.builder();
                } else {
                    continue;
                }
            }

            if (raw.startsWith("--- ")) {
                current.oldPath(stripPrefix(raw.substring(4).trim()));
            } else if (raw.startsWith("+++ ")) {
                current.newPath(stripPrefix(raw.substring(4).trim()));
            } else if (raw.startsWith("@@ ")) {
                if (hunkLines != null) {
                    current.addHunk(buildHunk(hunkStartOld, hunkOldCount, hunkStartNew, hunkNewCount, hunkLines));
                }
                Matcher m = HUNK.matcher(raw);
                if (!m.matches()) {
                    hunkLines = null;
                    continue;
                }
                hunkStartOld = Integer.parseInt(m.group(1));
                hunkOldCount = m.group(2) == null ? 1 : Integer.parseInt(m.group(2));
                hunkStartNew = Integer.parseInt(m.group(3));
                hunkNewCount = m.group(4) == null ? 1 : Integer.parseInt(m.group(4));
                oldLine = hunkStartOld;
                newLine = hunkStartNew;
                hunkLines = new ArrayList<>();
            } else if (hunkLines != null) {
                if (raw.startsWith("+")) {
                    hunkLines.add(new DiffLine(DiffLine.Kind.ADD, raw.substring(1), null, newLine++));
                } else if (raw.startsWith("-")) {
                    hunkLines.add(new DiffLine(DiffLine.Kind.REMOVE, raw.substring(1), oldLine++, null));
                } else if (raw.startsWith("\\")) {
                    // "\ No newline at end of file"
                } else {
                    String text = raw.startsWith(" ") ? raw.substring(1) : raw;
                    hunkLines.add(new DiffLine(DiffLine.Kind.CONTEXT, text, oldLine++, newLine++));
                }
            }
        }

        if (current != null) {
            if (hunkLines != null) {
                current.addHunk(buildHunk(hunkStartOld, hunkOldCount, hunkStartNew, hunkNewCount, hunkLines));
            }
            files.add(current.build());
        }
        return new Patch(files);
    }

    private int hunkStartOld;
    private int hunkOldCount;
    private int hunkStartNew;
    private int hunkNewCount;

    private static Hunk buildHunk(int oldStart, int oldCount, int newStart, int newCount,
                                  List<DiffLine> lines) {
        if (lines == null) {
            return null;
        }
        return new Hunk(oldStart, oldCount, newStart, newCount, List.copyOf(lines));
    }

    private static String stripPrefix(String path) {
        if (path.equals("/dev/null")) {
            return path;
        }
        if (path.startsWith("a/") || path.startsWith("b/")) {
            return path.substring(2);
        }
        return path;
    }

    public record Patch(List<PatchFile> files) {
        public Patch {
            files = files == null ? List.of() : List.copyOf(files);
        }

        public PatchFile fileForPath(String path) {
            if (path == null) {
                return null;
            }
            return files.stream()
                    .filter(f -> path.equals(f.newPath()) || path.equals(f.oldPath())
                            || path.endsWith("/" + f.newPath()) || path.endsWith("/" + f.oldPath()))
                    .findFirst()
                    .orElse(null);
        }
    }

    public record PatchFile(String oldPath, String newPath, List<Hunk> hunks) {
        public PatchFile {
            hunks = hunks == null ? List.of() : List.copyOf(hunks);
        }

        static Builder builder() {
            return new Builder();
        }

        static final class Builder {
            private String oldPath = "";
            private String newPath = "";
            private final List<Hunk> hunks = new ArrayList<>();

            Builder oldPath(String p) { oldPath = p; return this; }
            Builder newPath(String p) { newPath = p; return this; }
            Builder addHunk(Hunk h) { if (h != null) hunks.add(h); return this; }
            PatchFile build() { return new PatchFile(oldPath, newPath, hunks); }
        }
    }

    public record Hunk(int oldStart, int oldCount, int newStart, int newCount,
                       List<DiffLine> lines) {
    }

    public record DiffLine(Kind kind, String text, Integer oldLine, Integer newLine) {
        public enum Kind { CONTEXT, ADD, REMOVE }
    }
}
