package be.crydust.aesencrypter;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;

import org.junit.Test;

public class EncryptedPropertiesTest {

    @Test
    public void testEncryptedProperties() throws Exception {
        AESProperties p1 = new AESProperties();
        p1.setProperty("aaa", "bbb");
        assertEquals("bbb", p1.getProperty("aaa"));
        StringWriter sw = new StringWriter();
        p1.store(sw, null);
        String encrypted = sw.toString();
        System.out.println(encrypted);
        assertEquals(-1, encrypted.indexOf("bbb"));

        InputStream is = new ByteArrayInputStream(encrypted.getBytes("ASCII"));
        AESProperties p2 = new AESProperties();
        p2.load(is);
        assertEquals("bbb", p2.getProperty("aaa"));
    }
}
