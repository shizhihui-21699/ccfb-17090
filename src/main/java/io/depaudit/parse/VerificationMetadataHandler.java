package io.depaudit.parse;

import io.depaudit.model.ArtifactEntry;
import io.depaudit.model.ArtifactRef;
import io.depaudit.model.ComponentEntry;
import io.depaudit.model.HashAlgorithm;
import io.depaudit.model.TrustedKey;
import io.depaudit.model.VerificationMetadata;
import org.xml.sax.Attributes;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * SAX handler that builds a {@link VerificationMetadata} and records source line numbers.
 *
 * <p>Kept package-private and separate from the hardened parser factory so it can be unit-tested
 * against hand-written XML without going through the file-system entry point.
 */
final class VerificationMetadataHandler extends DefaultHandler {

    private static final String ROOT = "verification-metadata";
    private static final Set<String> TOGGLES = Set.of("verify-metadata", "verify-signatures");

    /**
     * Container elements that are fully modelled. Anything not listed here and not handled by an
     * explicit case above is recorded as unmodelled content, so a newly injected element cannot
     * disappear simply because this tool did not expect it.
     */
    private static final Set<String> CONTAINERS = Set.of(
            "configuration",
            "configuration/trusted-keys",
            "configuration/ignored-keys",
            "components",
            "components/component");

    private Locator locator;
    private final Deque<String> stack = new ArrayDeque<>();

    private boolean rootSeen;
    private boolean verifyMetadata = true;
    private boolean verifySignatures = false;
    private final List<TrustedKey> trustedKeys = new ArrayList<>();
    private final List<String> ignoredKeys = new ArrayList<>();
    private final List<ComponentEntry> components = new ArrayList<>();
    private final List<String> unknown = new ArrayList<>();

    // Component under construction.
    private ArtifactRef compCoords;
    private boolean compRegex;
    private int compLine;
    private List<ArtifactEntry> compArtifacts = new ArrayList<>();

    // Artifact under construction.
    private String artName;
    private int artLine;
    private List<ArtifactEntry.Digest> artDigests = new ArrayList<>();
    private List<String> artPgp = new ArrayList<>();

    // Trusted-key under construction.
    private String tkId;
    private String tkGroup;
    private String tkName;
    private String tkVersion;
    private boolean tkRegex;
    private int tkLine;
    private List<ArtifactRef> tkTrusting = new ArrayList<>();
    private final StringBuilder tkBody = new StringBuilder();

    // Character data for the boolean toggles.
    private final StringBuilder toggleText = new StringBuilder();

    private final String sourceName;

    VerificationMetadataHandler(String sourceName) {
        this.sourceName = sourceName;
    }

    private int line() {
        return locator == null ? 0 : locator.getLineNumber();
    }

    @Override
    public void setDocumentLocator(Locator locator) {
        this.locator = locator;
    }

    @Override
    public void startElement(String uri, String localName, String qName, Attributes atts)
            throws SAXException {
        String name = tagName(localName, qName);

        if (!rootSeen) {
            if (!ROOT.equals(name)) {
                throw new SAXException("Not a Gradle verification metadata file: root element is <"
                        + name + ">");
            }
            rootSeen = true;
            // The root is pushed as the empty path so children see paths relative to it, e.g.
            // "configuration/verify-metadata" rather than "verification-metadata/configuration/...".
            stack.push("");
            return;
        }

        String parent = stack.isEmpty() ? "" : stack.peek();
        String path = parent.isEmpty() ? name : parent + "/" + name;

        switch (path) {
            case "configuration/verify-metadata", "configuration/verify-signatures" ->
                    toggleText.setLength(0);
            case "configuration/ignored-keys/ignored-key" -> {
                String id = atts.getValue("id");
                if (id != null && !id.isBlank()) {
                    ignoredKeys.add(id.trim().toUpperCase(Locale.ROOT));
                }
            }
            case "configuration/trusted-artifacts/trust" ->
                    unknown.add("trusted-artifact " + coords(atts) + " at line " + line());
            case "configuration/trusted-keys/trusted-key" -> {
                tkId = atts.getValue("id");
                tkGroup = atts.getValue("group");
                tkName = atts.getValue("name");
                tkVersion = blankToNull(atts.getValue("version"));
                tkRegex = "true".equalsIgnoreCase(atts.getValue("regex"));
                tkLine = line();
                tkTrusting = new ArrayList<>();
                tkBody.setLength(0);
            }
            case "configuration/trusted-keys/trusted-key/trusting" -> tkTrusting.add(
                    new ArtifactRef(orEmpty(atts.getValue("group")),
                            orEmpty(atts.getValue("name")),
                            blankToNull(atts.getValue("version"))));
            case "components/component" -> {
                compCoords = new ArtifactRef(orEmpty(atts.getValue("group")),
                        orEmpty(atts.getValue("name")),
                        blankToNull(atts.getValue("version")));
                compRegex = "true".equalsIgnoreCase(atts.getValue("regex"));
                compLine = line();
                compArtifacts = new ArrayList<>();
            }
            case "components/component/artifact" -> {
                artName = orEmpty(atts.getValue("name"));
                artLine = line();
                artDigests = new ArrayList<>();
                artPgp = new ArrayList<>();
            }
            case "components/component/artifact/pgp" -> {
                String v = atts.getValue("value");
                if (v != null && !v.isBlank()) {
                    artPgp.add(v.trim().toUpperCase(Locale.ROOT));
                }
            }
            default -> {
                if (isDigestPath(path)) {
                    HashAlgorithm algorithm = HashAlgorithm.fromXmlName(name).orElseThrow();
                    String value = atts.getValue("value");
                    if (value != null) {
                        artDigests.add(new ArtifactEntry.Digest(algorithm, value,
                                blankToNull(atts.getValue("origin")),
                                blankToNull(atts.getValue("reason")),
                                false, line()));
                    } else {
                        unknown.add("<" + name + "> without value at line " + line());
                    }
                } else if ("also-trust".equals(name)
                        && "components/component/artifact".equals(parentPath(parent))) {
                    // <sha256 value="A"><also-trust value="B"/></sha256>
                    String algTag = lastSegment(parent);
                    HashAlgorithm algorithm = HashAlgorithm.fromXmlName(algTag).orElse(null);
                    String value = atts.getValue("value");
                    if (algorithm != null && value != null) {
                        artDigests.add(new ArtifactEntry.Digest(
                                algorithm, value, null, null, true, line()));
                    } else {
                        unknown.add("<also-trust> under <" + algTag + "> at line " + line());
                    }
                } else if (!CONTAINERS.contains(path)) {
                    // Anything else under the document root or inside a modelled container is
                    // recorded, never silently dropped: that is how a hand-injected element would
                    // otherwise hide.
                    unknown.add("<" + name + "> at " + path + " line " + line());
                }
            }
        }
        stack.push(path);
    }

    @Override
    public void characters(char[] ch, int start, int length) {
        if (stack.isEmpty() || stack.peek().isEmpty()) {
            return;
        }
        String top = lastSegment(stack.peek());
        if ("trusted-key".equals(top)) {
            tkBody.append(ch, start, length);
        } else if (TOGGLES.contains(top) && secondFromTop().equals("configuration")) {
            toggleText.append(ch, start, length);
        }
    }

    @Override
    public void endElement(String uri, String localName, String qName) {
        if (stack.isEmpty() || stack.peek().isEmpty()) {
            // Closing the root element itself.
            if (!stack.isEmpty()) {
                stack.pop();
            }
            return;
        }
        String path = stack.peek();

        switch (path) {
            case "configuration/verify-metadata" ->
                    verifyMetadata = "true".equalsIgnoreCase(toggleText.toString().trim());
            case "configuration/verify-signatures" ->
                    verifySignatures = "true".equalsIgnoreCase(toggleText.toString().trim());
            case "configuration/trusted-keys/trusted-key" -> trustedKeys.add(new TrustedKey(
                    tkId, tkGroup, tkName, tkVersion, tkRegex,
                    List.copyOf(tkTrusting), cleanInlineKey(tkBody), tkLine));
            case "components/component/artifact" -> compArtifacts.add(new ArtifactEntry(
                    artName, List.copyOf(artDigests), List.copyOf(artPgp), artLine));
            case "components/component" -> components.add(new ComponentEntry(
                    compCoords, List.copyOf(compArtifacts), compRegex, compLine));
            default -> { }
        }
        stack.pop();
    }

    VerificationMetadata toMetadata() throws MetadataParseException {
        if (!rootSeen) {
            throw new MetadataParseException("Empty or non-XML document: " + sourceName);
        }
        return new VerificationMetadata(
                new VerificationMetadata.Configuration(
                        verifyMetadata, verifySignatures,
                        List.copyOf(trustedKeys), List.copyOf(ignoredKeys)),
                List.copyOf(components),
                List.copyOf(unknown));
    }

    // -------------------------------------------------------------- helpers

    private String secondFromTop() {
        var it = stack.iterator();
        if (it.hasNext()) {
            it.next();
        }
        String parent = it.hasNext() ? it.next() : "";
        return lastSegment(parent);
    }

    private static String lastSegment(String path) {
        int i = path.lastIndexOf('/');
        return i < 0 ? path : path.substring(i + 1);
    }

    private static String parentPath(String path) {
        int i = path.lastIndexOf('/');
        return i < 0 ? "" : path.substring(0, i);
    }

    /** Strip any namespace prefix a non-namespace-aware parser might leave on the name. */
    private static String tagName(String localName, String qName) {
        if (localName != null && !localName.isEmpty()) {
            return localName;
        }
        int colon = qName.indexOf(':');
        return colon < 0 ? qName : qName.substring(colon + 1);
    }

    private static boolean isDigestPath(String path) {
        String prefix = "components/component/artifact/";
        return path.startsWith(prefix)
                && HashAlgorithm.fromXmlName(path.substring(prefix.length())).isPresent();
    }

    private static String coords(Attributes atts) {
        String g = orEmpty(atts.getValue("group"));
        String n = orEmpty(atts.getValue("name"));
        String v = atts.getValue("version");
        return v == null ? g + ":" + n : g + ":" + n + ":" + v;
    }

    private static String cleanInlineKey(StringBuilder body) {
        String s = body.toString().replaceAll("\\s+", "");
        return s.isEmpty() ? null : s;
    }

    private static String orEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
