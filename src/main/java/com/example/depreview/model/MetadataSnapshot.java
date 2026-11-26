package com.example.depreview.model;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public record MetadataSnapshot(Path path, List<MetadataRecord> records) {

    public MetadataSnapshot {
        records = records == null ? List.of() : List.copyOf(records);
    }

    public Map<String, List<MetadataRecord>> byGa() {
        return records.stream().collect(Collectors.groupingBy(
                r -> r.coordinates().ga(),
                java.util.TreeMap::new,
                Collectors.toList()));
    }
}
