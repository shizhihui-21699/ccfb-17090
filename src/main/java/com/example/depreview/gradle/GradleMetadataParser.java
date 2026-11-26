package com.example.depreview.gradle;

import com.example.depreview.model.Coordinates;
import com.example.depreview.model.HashValue;
import com.example.depreview.model.MetadataRecord;
import com.example.depreview.model.MetadataSnapshot;
import com.example.depreview.model.SignerRef;
import com.example.depreview.model.SourceRef;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.Locator;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.XMLConstants;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Namespace-tolerant parser for Gradle {@code verification-metadata.xml}.
 *
 * <p>The parser also accepts source URLs embedded by forks/custom schemas, which is useful when
 * the malicious merge request changes both a checksum and a provenance URL. XML parsing is
 * hardened against XXE because these files are untrusted in a merge request.
 */
public final class GradleMetadataParser {

    public GradleParseResult parse(Path path) throws IOException {
        try (InputStream in = Files.newInputStream(path)) {
            return parse(in, path.toString());
        }
    }

    public GradleParseResult parse(InputStream inputStream, String displayName) throws IOException {
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setXIncludeAware(false);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);

            SAXParser parser = factory.newSAXParser();
            Handler handler = new Handler(displayName);
            parser.parse(new InputSource(inputStream), handler);
            return new GradleParseResult(
                    new MetadataSnapshot(Path.of(displayName), handler.records),
                    Set.copyOf(handler.trustedKeys),
                    List.copyOf(handler.keyServers));
        } catch (Exception e) {
            if (e instanceof IOException io) {
                throw io;
            }
            throw new IOException("Cannot parse dependency verification metadata: " + displayName
                    + ": " + e.getMessage(), e);
        }
    }

    public record GradleParseResult(
            MetadataSnapshot snapshot,
            Set<String> trustedKeyIds,
            List<String> keyServers) {
    }

    private static final class Handler extends DefaultHandler {
        private final String displayName;
        private final List<MetadataRecord> records = new ArrayList<>();
        private final Set<String> trustedKeys = new LinkedHashSet<>();
        private final List<String> keyServers = new ArrayList<>();
        private final StringBuilder text = new StringBuilder();

        private Locator locator;
        private Coordinates component;
        private ArtifactState artifact;
        private HashState hash;
        private String textElement;

        private Handler(String displayName) {
            this.displayName = displayName;
        }

        @Override
        public void setDocumentLocator(Locator locator) {
            this.locator = locator;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            text.setLength(0);
            String name = localName == null || localName.isBlank() ? qName : localName;
            int line = line();

            if ("component".equals(name)) {
                String group = attr(attributes, "group", "groupId");
                String artifact = attr(attributes, "name", "artifactId");
                String version = attr(attributes, "version");
                if (!group.isBlank() && !artifact.isBlank() && !version.isBlank()) {
                    component = new Coordinates(group, artifact, version);
                }
            } else if ("artifact".equals(name) && component != null) {
                artifact = new ArtifactState(attr(attributes, "name"), line);
                collectUrlAttributes(name, attributes, line);
            } else if (artifact != null) {
                if (isHashElement(name, attributes)) {
                    String algorithm = firstNonBlank(attr(attributes, "algorithm"),
                            attr(attributes, "algo"), name);
                    hash = new HashState(algorithm, attr(attributes, "value"),
                            attr(attributes, "origin"), line);
                } else if ("also-trust".equals(name) && hash != null) {
                    String trustedValue = attr(attributes, "value");
                    if (!trustedValue.isBlank()) {
                        hash.alsoTrust.add(trustedValue);
                    }
                } else if ("pgp".equals(name) || "signature".equals(name)) {
                    String key = firstNonBlank(attr(attributes, "value"),
                            attr(attributes, "key"), attr(attributes, "keyId"),
                            attr(attributes, "id"));
                    if (!key.isBlank()) {
                        artifact.signers.add(new SignerRef(key, line));
                    }
                }
                collectUrlAttributes(name, attributes, line);
            }

            if ("trusted-key".equals(name)) {
                String key = firstNonBlank(attr(attributes, "id"), attr(attributes, "value"),
                        attr(attributes, "fingerprint"), attr(attributes, "keyId"));
                if (!key.isBlank()) {
                    trustedKeys.add(key.toUpperCase());
                }
            }
            if ("key-server".equals(name)) {
                String server = firstNonBlank(attr(attributes, "uri"), attr(attributes, "url"));
                if (!server.isBlank()) {
                    keyServers.add(server);
                }
            }
            textElement = name;
        }

        @Override
        public void characters(char[] ch, int start, int length) {
            text.append(ch, start, length);
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            String name = localName == null || localName.isBlank() ? qName : localName;
            String body = text.toString().trim();

            if (hash != null && (isHashElement(name, null) || "hash".equals(name))) {
                if ((hash.value == null || hash.value.isBlank()) && !body.isBlank()) {
                    hash.value = body;
                }
                if (!hash.algorithm.isBlank() && hash.value != null && !hash.value.isBlank()) {
                    artifact.hashes.computeIfAbsent(hash.algorithm, ignored -> new ArrayList<>())
                            .add(new HashValue(hash.algorithm, hash.value, hash.origin,
                                    hash.line, hash.alsoTrust));
                }
                hash = null;
            } else if (artifact != null && textElement != null && textElement.equals(name)
                    && body.contains("://") && isSourceElement(name)) {
                artifact.sources.add(new SourceRef(body, name, line()));
            }

            if ("artifact".equals(name) && artifact != null && component != null) {
                records.add(new MetadataRecord(
                        component,
                        artifact.name,
                        artifact.hashes,
                        artifact.sources,
                        artifact.signers,
                        artifact.line));
                artifact = null;
            }
            if ("component".equals(name)) {
                component = null;
            }
            text.setLength(0);
            textElement = null;
        }

        private void collectUrlAttributes(String elementName, Attributes attributes, int line) {
            if (artifact == null || attributes == null) {
                return;
            }
            for (int i = 0; i < attributes.getLength(); i++) {
                String local = attributes.getLocalName(i);
                if (local == null || local.isBlank()) {
                    local = attributes.getQName(i);
                }
                local = local == null ? "" : local.toLowerCase();
                String value = attributes.getValue(i);
                if (value == null || value.isBlank()) {
                    continue;
                }
                if (local.equals("url") || local.equals("uri") || local.equals("href")
                        || local.equals("sourceurl") || local.equals("repositoryurl")
                        || local.equals("source") || local.equals("repository")) {
                    artifact.sources.add(new SourceRef(value.trim(),
                            elementName + "@" + local, line));
                } else if ((local.equals("origin") || local.equals("reason"))
                        && value.contains("://")) {
                    artifact.sources.add(new SourceRef(value.trim(),
                            elementName + "@" + local, line));
                }
            }
        }

        private static boolean isHashElement(String name, Attributes attributes) {
            if (name == null) {
                return false;
            }
            String n = name.toLowerCase();
            return n.equals("md5") || n.equals("sha1") || n.equals("sha-1")
                    || n.equals("sha256") || n.equals("sha-256")
                    || n.equals("sha384") || n.equals("sha-384")
                    || n.equals("sha512") || n.equals("sha-512")
                    || n.startsWith("sha3-")
                    || (attributes != null && !attr(attributes, "algorithm").isBlank()
                        && !attr(attributes, "value").isBlank());
        }

        private static boolean isSourceElement(String name) {
            String n = name.toLowerCase();
            return n.equals("source") || n.equals("repository") || n.equals("url")
                    || n.equals("origin") || n.equals("downloadurl");
        }

        private Integer line() {
            if (locator == null) {
                return null;
            }
            int lineNumber = locator.getLineNumber();
            return lineNumber > 0 ? lineNumber : null;
        }

        private static String attr(Attributes attributes, String... names) {
            for (String name : names) {
                String value = attributes.getValue(name);
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
                for (int i = 0; i < attributes.getLength(); i++) {
                    String local = attributes.getLocalName(i);
                    if (name.equalsIgnoreCase(local)) {
                        String v = attributes.getValue(i);
                        if (v != null && !v.isBlank()) {
                            return v.trim();
                        }
                    }
                }
            }
            return "";
        }

        private static String firstNonBlank(String... values) {
            for (String value : values) {
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
            }
            return "";
        }
    }

    private static final class ArtifactState {
        private final String name;
        private final Integer line;
        private final Map<String, List<HashValue>> hashes = new LinkedHashMap<>();
        private final List<SourceRef> sources = new ArrayList<>();
        private final List<SignerRef> signers = new ArrayList<>();

        private ArtifactState(String name, Integer line) {
            this.name = name == null ? "" : name;
            this.line = line;
        }
    }

    private static final class HashState {
        private final String algorithm;
        private String value;
        private final String origin;
        private final Integer line;
        private final List<String> alsoTrust = new ArrayList<>();

        private HashState(String algorithm, String value, String origin, Integer line) {
            this.algorithm = algorithm == null ? "" : algorithm.replace("-", "").toLowerCase();
            this.value = value;
            this.origin = origin;
            this.line = line;
        }
    }
}
