package io.depaudit.verify;

/**
 * A repository the tool may consult, as configured by the <em>reviewer</em>.
 *
 * <p>Deliberately not derived from the metadata file: an attacker who can edit the file could
 * otherwise add a repository that serves their forged artifact and have the tool confirm it. What
 * repositories exist is a property of the review environment, not of the file under review.
 *
 * @param id       short stable label used in reports, e.g. {@code maven-central}
 * @param baseUrl  repository root, without a trailing slash
 * @param tier     how much a match here is worth
 * @param offline  when true, never make network calls to this repository (used for the internal
 *                 mirror in air-gapped review, or to replay from a local cache)
 */
public record RepositoryConfig(String id, String baseUrl, TrustTier tier, boolean offline) {

    public RepositoryConfig {
        if (baseUrl != null && baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
    }

    public static RepositoryConfig mavenCentral() {
        return new RepositoryConfig("maven-central", "https://repo1.maven.org/maven2",
                TrustTier.CANONICAL, false);
    }

    public String urlFor(String groupPath, String fileName) {
        return baseUrl + "/" + groupPath + "/" + fileName;
    }

    @Override
    public String toString() {
        return id;
    }
}
