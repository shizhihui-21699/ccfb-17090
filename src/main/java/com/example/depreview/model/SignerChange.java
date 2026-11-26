package com.example.depreview.model;

public record SignerChange(
        String oldKeyId,
        String newKeyId,
        Integer oldLine,
        Integer newLine) {
}
