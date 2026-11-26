package com.example.depreview.model;

import java.util.List;

public record BuildEvidence(
        boolean buildPatchProvided,
        boolean newVersionDeclared,
        boolean oldVersionRemoved,
        List<String> matchingLines) {

    public static BuildEvidence notProvided() {
        return new BuildEvidence(false, false, false, List.of());
    }

    public static BuildEvidence none() {
        return new BuildEvidence(true, false, false, List.of());
    }
}
