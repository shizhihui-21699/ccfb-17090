package com.example.depreview.model;

public record UrlChange(
        String oldUrl,
        String newUrl,
        Integer oldLine,
        Integer newLine) {

    public boolean changed() {
        return oldUrl != null && newUrl != null && !oldUrl.equals(newUrl);
    }
}
