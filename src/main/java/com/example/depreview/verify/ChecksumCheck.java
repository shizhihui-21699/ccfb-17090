package com.example.depreview.verify;

public record ChecksumCheck(
        String algorithm,
        String metadataValue,
        String remoteValue,
        String repositoryId,
        String checksumUrl,
        boolean found,
        boolean matches) {

    public static ChecksumCheck notFound(String algorithm, String metadataValue,
                                         String repositoryId, String url) {
        return new ChecksumCheck(algorithm, metadataValue, null, repositoryId, url, false, false);
    }

    public static ChecksumCheck error(String algorithm, String metadataValue,
                                      String repositoryId, String url) {
        return new ChecksumCheck(algorithm, metadataValue, null, repositoryId, url, false, false);
    }
}
