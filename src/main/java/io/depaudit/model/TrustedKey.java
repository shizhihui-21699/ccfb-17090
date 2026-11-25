package io.depaudit.model;

import java.util.List;

/**
 * One {@code <trusted-key>} declaration under {@code <configuration><trusted-keys>}.
 *
 * <p>In Gradle's metadata file a trusted key is a <em>scoping</em> declaration: it says
 * "signatures by this key are accepted for artifacts matching these coordinates". The trusted-key
 * set is arguably the most security-sensitive part of the file, because a key added here can vouch
 * for an arbitrary number of future artifacts — including ones added later by someone else. The
 * tool therefore diffs these explicitly rather than treating configuration changes as noise.
 *
 * @param id         upper-cased hex key id (Gradle writes the long id or the full fingerprint)
 * @param group      optional group scope; {@code null} or a wildcard means "all groups"
 * @param name       optional artifact-name scope
 * @param version    optional version scope
 * @param regex      whether the group/name scopes are regexes rather than literal prefixes
 * @param trusting   nested {@code <trusting>} clauses, which re-scope the key to further coordinates
 * @param inlineKey  base64 key material embedded directly in the element body, if any. Gradle
 *                   writes this only when a project deliberately exports keys into the file; a
 *                   key appearing here acquires trust without any external lookup.
 * @param line       1-based line of the element, or 0 if unknown
 */
public record TrustedKey(
        String id,
        String group,
        String name,
        String version,
        boolean regex,
        List<ArtifactRef> trusting,
        String inlineKey,
        int line) {

    public TrustedKey {
        id = id == null ? null : id.trim().toUpperCase(java.util.Locale.ROOT);
        trusting = trusting == null ? List.of() : List.copyOf(trusting);
        inlineKey = inlineKey == null || inlineKey.isBlank() ? null : inlineKey;
    }

    /** True when the key is unscoped, i.e. it can vouch for any artifact in the build. */
    public boolean isUnscoped() {
        boolean wildcardGroup = group == null || group.isBlank() || "*".equals(group.trim());
        boolean wildcardName = name == null || name.isBlank() || "*".equals(name.trim());
        return wildcardGroup && wildcardName && version == null && trusting.isEmpty();
    }

    public boolean hasInlineKey() {
        return inlineKey != null;
    }

    public String scopeDescription() {
        StringBuilder sb = new StringBuilder();
        if (group != null) {
            sb.append("group=").append(group);
        }
        if (name != null) {
            sb.append(sb.isEmpty() ? "" : " ").append("name=").append(name);
        }
        if (version != null) {
            sb.append(sb.isEmpty() ? "" : " ").append("version=").append(version);
        }
        if (regex) {
            sb.append(sb.isEmpty() ? "" : " ").append("(regex)");
        }
        for (ArtifactRef t : trusting) {
            sb.append(sb.isEmpty() ? "" : " ").append("trusting ").append(t.gav());
        }
        if (hasInlineKey()) {
            sb.append(sb.isEmpty() ? "" : " ").append("(inline key material)");
        }
        return sb.isEmpty() ? "<all artifacts>" : sb.toString();
    }

    /** Short display form: last 16 hex chars, which is what humans recognise as a key id. */
    public String shortId() {
        if (id == null || id.isEmpty()) {
            return "<missing-id>";
        }
        return id.length() <= 16 ? id : "…" + id.substring(id.length() - 16);
    }
}
