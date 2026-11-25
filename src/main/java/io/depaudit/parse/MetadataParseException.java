package io.depaudit.parse;

/** Raised when a metadata file cannot be parsed at all. Content errors are reported separately. */
public class MetadataParseException extends Exception {
    private static final long serialVersionUID = 1L;

    public MetadataParseException(String message) {
        super(message);
    }

    public MetadataParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
