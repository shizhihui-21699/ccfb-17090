package com.example.depreview.gradle;

import com.example.depreview.model.MetadataRecord;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GradleMetadataParserTest {

    @Test
    void parsesComponentHashesPinsAndCustomSource() throws Exception {
        String xml = """
                <?xml version="1.0"?>
                <verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
                  <configuration>
                    <trusted-keys><trusted-key id="ABCDEF0123456789"/></trusted-keys>
                  </configuration>
                  <components>
                    <component group="com.example" name="lib" version="1.2.3">
                      <artifact name="lib-1.2.3.jar">
                        <source url="https://mirror.example/lib.jar"/>
                        <sha256 value="%s" origin="test"/>
                        <pgp value="ABCDEF0123456789"/>
                      </artifact>
                    </component>
                  </components>
                </verification-metadata>
                """.formatted("a".repeat(64));

        GradleMetadataParser.GradleParseResult result = new GradleMetadataParser()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), "test.xml");

        assertEquals(1, result.snapshot().records().size());
        MetadataRecord record = result.snapshot().records().get(0);
        assertEquals("com.example:lib:1.2.3", record.coordinates().gav());
        assertEquals("sha256", record.hashes().get("sha256").get(0).algorithm());
        assertEquals("https://mirror.example/lib.jar", record.sources().get(0).url());
        assertEquals("ABCDEF0123456789", record.signers().get(0).keyId());
        assertTrue(result.trustedKeyIds().contains("ABCDEF0123456789"));
        assertNotNull(record.hashes().get("sha256").get(0).line());
    }

    @Test
    void rejectsDoctypeToPreventXxe() {
        String xml = """
                <?xml version="1.0"?>
                <!DOCTYPE verification-metadata [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                <verification-metadata>&xxe;</verification-metadata>
                """;
        assertThrows(Exception.class, () -> new GradleMetadataParser()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)), "xxe.xml"));
    }
}
