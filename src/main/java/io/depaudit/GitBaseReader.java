package io.depaudit;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Fetches the previous revision of a metadata file straight from git.
 *
 * <p>In a merge request there is no "old file" on disk — the working tree only has the proposed
 * version. Making the reviewer export the previous revision by hand is exactly the friction that
 * causes a security check to be skipped, so the tool reads it from the base commit itself.
 *
 * <p>Uses the {@code git} command rather than reimplementing object access: the file is read from a
 * diff against a commit, which is what the review system is already doing, so the bytes match what
 * the reviewer sees. Arguments are passed as a real argument vector (never a shell string) so a
 * revision name cannot be turned into shell syntax.
 */
public final class GitBaseReader {

    /**
     * Materialises {@code pathAtRev} from {@code rev} into a temporary file and returns its path.
     * If the file does not exist at that revision, an empty placeholder is returned, which makes the
     * audit treat the whole file as newly added rather than failing.
     */
    public Path materialise(String rev, Path pathAtRev) throws IOException {
        List<String> cmd = new ArrayList<>(List.of("git", "show", rev + ":" + toPosix(pathAtRev)));
        ProcessResult r = exec(cmd);
        if (r.exitCode != 0) {
            // Not present at that revision: the metadata file is being introduced in this change.
            Path empty = Files.createTempFile("depaudit-old-", ".xml");
            empty.toFile().deleteOnExit();
            return empty;
        }
        Path out = Files.createTempFile("depaudit-old-", ".xml");
        out.toFile().deleteOnExit();
        Files.write(out, r.stdoutBytes);
        return out;
    }

    /** True when the current directory is inside a git work tree (checked cheaply). */
    public boolean inGitRepository() {
        try {
            return exec(List.of("git", "rev-parse", "--is-inside-work-tree")).exitCode == 0;
        } catch (IOException e) {
            return false;
        }
    }

    private record ProcessResult(int exitCode, byte[] stdoutBytes) { }

    private static ProcessResult exec(List<String> cmd) throws IOException {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        Process p = pb.start();
        try (InputStream in = p.getInputStream()) {
            byte[] stdout = in.readAllBytes();
            boolean finished = p.waitFor(30, TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                throw new IOException("git command timed out: " + String.join(" ", cmd));
            }
            return new ProcessResult(p.exitValue(), stdout);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
            throw new IOException("interrupted running git", e);
        }
    }

    static String toPosix(Path p) {
        return p.toString().replace('\\', '/');
    }
}
