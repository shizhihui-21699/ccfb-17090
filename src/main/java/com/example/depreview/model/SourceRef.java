package com.example.depreview.model;

public record SourceRef(String url, String kind, Integer line) {
    public SourceRef {
        url = url == null ? "" : url.trim();
        kind = kind == null ? "url" : kind;
    }
}
