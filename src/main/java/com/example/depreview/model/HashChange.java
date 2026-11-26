package com.example.depreview.model;

public record HashChange(
        String algorithm,
        String oldValue,
        String newValue,
        Integer oldLine,
        Integer newLine) {

    public boolean valueChanged() {
        return oldValue != null && newValue != null && !oldValue.equals(newValue);
    }

    public boolean added() {
        return oldValue == null && newValue != null;
    }

    public boolean removed() {
        return oldValue != null && newValue == null;
    }
}
