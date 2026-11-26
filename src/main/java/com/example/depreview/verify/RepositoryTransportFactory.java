package com.example.depreview.verify;

import com.example.depreview.config.RepositoryConfig;

public final class RepositoryTransportFactory {

    private RepositoryTransportFactory() {
    }

    public static RepositoryTransport create(RepositoryConfig config, int timeoutSeconds) {
        if (config.fileRepository()) {
            return new FileRepositoryTransport(config);
        }
        return new HttpRepositoryTransport(config, timeoutSeconds);
    }
}
