/**
 * OWASP Enterprise Security API (ESAPI)
 *
 * This file is part of the Open Web Application Security Project (OWASP)
 * Enterprise Security API (ESAPI) project. For details, please see
 * <a
 * href="http://www.owasp.org/index.php/ESAPI">http://www.owasp.org/index.php/ESAPI</a>.
 *
 * Copyright (c) 2007 - The OWASP Foundation
 *
 * The ESAPI is published by OWASP under the BSD license. You should read and
 * accept the LICENSE before you use, modify, and/or redistribute this software.
 *
 * @author Jeff Williams <a href="http://www.aspectsecurity.com">Aspect
 * Security</a>
 * @created 2007
 */
package be.crydust.aesencrypter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Iterator;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * The Class EncryptedPropertiesTest.
 *
 * @author Jeff Williams (jeff.williams@aspectsecurity.com)
 */
public class OwaspEncryptedPropertiesTest {

    /**
     * Test of getProperty method, of class org.owasp.esapi.EncryptedProperties.
     *
     * @throws EncryptionException the encryption exception
     */
    @Test
    public void testGetProperty() throws EncryptionException, Exception {
        System.out.println("getProperty");
        DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
        String name = "name";
        String value = "value";
        instance.setProperty(name, value);
        String result = instance.getProperty(name);
        assertEquals(value, result);
        assertNull(instance.getProperty("ridiculous"));
    }

    /**
     * Test of setProperty method, of class org.owasp.esapi.EncryptedProperties.
     *
     * @throws EncryptionException the encryption exception
     */
    @Test
    public void testSetProperty() throws EncryptionException, Exception {
        System.out.println("setProperty");
        DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
        String name = "name";
        String value = "value";
        instance.setProperty(name, value);
        String result = instance.getProperty(name);
        assertEquals(value, result);

        instance.setProperty(name, "");
        result = instance.getProperty(name);
        assertEquals(result, "");

        try {
            instance.setProperty(null, value);
            fail("testSetProperty(): Null property name did not result in expected exception.");
        } catch (Exception e) {
            assertTrue(e instanceof AESException);
        }
        try {
            instance.setProperty(name, null);
            fail("testSetProperty(): Null property value did not result in expected exception.");
        } catch (Exception e) {
            assertTrue(e instanceof AESException);
        }
        try {
            instance.setProperty(null, null);
            fail("testSetProperty(): Null property name and valud did not result in expected exception.");
        } catch (Exception e) {
            assertTrue(e instanceof AESException);
        }
    }

    /**
     * Test the behavior when the requested key does not exist.
     */
    @Test
    public void testNonExistantKeyValue() throws Exception {
        DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
        assertNull(instance.getProperty("not.there"));
    }

    /**
     * Test of keySet method, of class org.owasp.esapi.EncryptedProperties.
     */
    @Test
    public void testKeySet() throws Exception {
        boolean sawTwo = false;
        boolean sawOne = false;

        System.out.println("keySet");
        DefaultEncryptedProperties instance = new DefaultEncryptedProperties();
        instance.setProperty("one", "two");
        instance.setProperty("two", "three");
        Iterator<Object> i = instance.keySet().iterator();
        while (i.hasNext()) {
            String key = (String) i.next();

            assertNotNull("key returned from keySet() iterator was null", key);
            if (key.equals("one")) {
                if (sawOne) {
                    fail("Key one seen more than once.");
                } else {
                    sawOne = true;
                }
            } else if (key.equals("two")) {
                if (sawTwo) {
                    fail("Key two seen more than once.");
                } else {
                    sawTwo = true;
                }
            } else {
                fail("Unset key " + key + " returned from keySet().iterator()");
            }
        }
        assertTrue("Key one was never seen", sawOne);
        assertTrue("Key two was never seen", sawTwo);
    }

    /**
     * Test storing and loading of encrypted properties.
     */
    @Test
    public void testStoreLoad() throws Exception {
        DefaultEncryptedProperties toLoad = new DefaultEncryptedProperties();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ByteArrayInputStream bais;
        boolean sawOne = false;
        boolean sawTwo = false;
        boolean sawSeuss = false;

        DefaultEncryptedProperties toStore = new DefaultEncryptedProperties();
        toStore.setProperty("one", "two");
        toStore.setProperty("two", "three");
        toStore.setProperty("seuss.schneier", "one fish, twofish, red fish, blowfish");
        toStore.store(baos, "testStore");

        bais = new ByteArrayInputStream(baos.toByteArray());
        toLoad.load(bais);

        for (Iterator<Object> i = toLoad.keySet().iterator(); i.hasNext();) {
            String key = (String) i.next();

            assertNotNull("key returned from keySet() iterator was null", key);
            if (key.equals("one")) {
                if (sawOne) {
                    fail("Key one seen more than once.");
                } else {
                    sawOne = true;
                    assertEquals("Key one's value was not two", "two", toLoad.getProperty("one"));
                }
            } else if (key.equals("two")) {
                if (sawTwo) {
                    fail("Key two seen more than once.");
                } else {
                    sawTwo = true;
                    assertEquals("Key two's value was not three", "three", toLoad.getProperty("two"));
                }
            } else if (key.equals("seuss.schneier")) {
                if (sawSeuss) {
                    fail("Key seuss.schneier seen more than once.");
                } else {
                    sawSeuss = true;
                    assertEquals("Key seuss.schneier's value was not expected value",
                            "one fish, twofish, red fish, blowfish",
                            toStore.getProperty("seuss.schneier"));
                }
            } else {
                fail("Unset key " + key + " returned from keySet().iterator()");
            }
        }
        assertTrue("Key one was never seen", sawOne);
        assertTrue("Key two was never seen", sawTwo);
    }

    @SuppressWarnings("serial")
    private static class EncryptionException extends Exception {
    }

    @SuppressWarnings("serial")
    private static class DefaultEncryptedProperties extends AESProperties {

        public DefaultEncryptedProperties() throws Exception {
            super();
        }
    }
}
