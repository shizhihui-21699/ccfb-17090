package io.depaudit.parse;

import io.depaudit.model.VerificationMetadata;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Entry point for parsing {@code verification-metadata.xml}.
 *
 * <p>Files in a merge request are <em>untrusted input</em>: whoever edits the metadata also
 * controls the bytes of this XML. The parser is therefore hardened against XXE, external entity
 * expansion and DTD-based DoS before it reads a single element, and never resolves anything over
 * the network because of file content.
 *
 * <p>The work is delegated to {@link VerificationMetadataHandler}, a streaming SAX handler. Streaming
 * rather than DOM because real projects' files run to tens of thousands of lines, and because the
 * review needs line numbers to point a reviewer at the exact entry in the pull request.
 */
public final class VerificationMetadataParser {

    public VerificationMetadata parse(Path file) throws MetadataParseException {
        try (InputStream in = Files.newInputStream(file)) {
            return parse(in, file.toString());
        } catch (IOException e) {
            throw new MetadataParseException("Cannot read " + file + ": " + e.getMessage(), e);
        }
    }

    public VerificationMetadata parse(InputStream in, String sourceName) throws MetadataParseException {
        VerificationMetadataHandler handler = new VerificationMetadataHandler(sourceName);
        try {
            SAXParser parser = factory().newSAXParser();
            InputSource src = new InputSource(in);
            src.setSystemId(sourceName);
            parser.parse(src, handler);
        } catch (SAXParseException e) {
            throw new MetadataParseException(
                    "Malformed XML in " + sourceName + " at line " + e.getLineNumber()
                            + ", column " + e.getColumnNumber() + ": " + e.getMessage(), e);
        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new MetadataParseException("Cannot parse " + sourceName + ": " + e.getMessage(), e);
        }
        return handler.toMetadata();
    }

    private static SAXParserFactory factory() throws ParserConfigurationException, SAXException {
        SAXParserFactory f = SAXParserFactory.newInstance();
        f.setNamespaceAware(true);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        f.setXIncludeAware(false);
        return f;
    }
}
