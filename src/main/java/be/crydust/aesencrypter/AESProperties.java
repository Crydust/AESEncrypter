package be.crydust.aesencrypter;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Set;

public class AESProperties extends Properties {

    private static final long serialVersionUID = 1L;
    private static final String password = "meXuF-Y5yeP:)698:oon^9gQ3OCgxc[JYrq|U56V5iq~H-G$2C";

    public AESProperties() {
        super();
    }

    public AESProperties(Properties defaults) {
        this();
        for (Object oKey : defaults.keySet()) {
            String key = (oKey instanceof String) ? (String) oKey : oKey.toString();
            String value = defaults.getProperty(key);
            this.setProperty(key, value);
        }
    }

    @Override
    public final synchronized String getProperty(String key) throws AESRuntimeException {
        if (key == null) {
            throw new NullPointerException("Property name may not be null.");
        }
        String encryptedValue = super.getProperty(key);
        if (encryptedValue != null) {
            try {
                return decrypt(encryptedValue);
            } catch (AESException ex) {
                throw new AESRuntimeException("getProperty failed for " + key, ex);
            }
        }
        return null;
    }

    @Override
    public final synchronized Object setProperty(String key, String value) throws AESRuntimeException {
        if (key == null) {
            throw new NullPointerException("Property name may not be null.");
        }
        if (value == null) {
            throw new NullPointerException("Property value may not be null.");
        }
        try {
            return super.setProperty(key, encrypt(value));
        } catch (AESException ex) {
            throw new AESRuntimeException("setProperty failed for " + key, ex);
        }
    }

    private synchronized String decrypt(String str) throws AESException {
        return AESEncrypter.decrypt(password, str);
    }

    private synchronized String encrypt(String str) throws AESException {
        return AESEncrypter.encrypt(password, str);
    }
    

    /**
     * This method has been overridden to throw an
     * {@code UnsupportedOperationException}
     */
    @Override
    public void list(PrintStream out) {
        throw new UnsupportedOperationException("This method has been removed for security.");
    }

    /**
     * This method has been overridden to throw an
     * {@code UnsupportedOperationException}
     */
    @Override
    public void list(PrintWriter out) {
        throw new UnsupportedOperationException("This method has been removed for security.");
    }

    /**
     * This method has been overridden to throw an
     * {@code UnsupportedOperationException}
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public Collection values() {
        throw new UnsupportedOperationException("This method has been removed for security.");
    }

    /**
     * This method has been overridden to throw an
     * {@code UnsupportedOperationException}
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public Set entrySet() {
        throw new UnsupportedOperationException("This method has been removed for security.");
    }

    /**
     * This method has been overridden to throw an
     * {@code UnsupportedOperationException}
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    @Override
    public Enumeration elements() {
        throw new UnsupportedOperationException("This method has been removed for security.");
    }

    /**
     * This method has been overridden to only accept Strings for key and value,
     * and to encrypt those Strings before storing them. Outside classes should
     * always use {@code setProperty} to add values to the Properties map. If an
     * outside class does erroneously call this method with non-String
     * parameters an {@code IllegalArgumentException} will be thrown.
     *
     * @param key	A String key to add
     * @param value A String value to add
     * @return	The old value associated with the specified key, or {@code null}
     * if the key did not exist.
     */
    @Override
    public synchronized Object put(Object key, Object value) {
        //if java.util.Properties is calling this method, just forward to the implementation in
        //the superclass (java.util.Hashtable)
        Throwable t = new Throwable();
        for (StackTraceElement trace : t.getStackTrace()) {
            if ("java.util.Properties".equals(trace.getClassName())) {
                return super.put(key, value);
            }
        }

        //otherwise, if both arguments are Strings, encrypt and store them
        if (key instanceof String && value instanceof String) {
            return setProperty((String) key, (String) value);
        }

        //other Object types are not allowed
        throw new IllegalArgumentException("This method has been overridden to only accept Strings for key and value.");
    }
    
    /**
     * This method has been overridden to not print out the keys and values
     * stored in this properties file.
     *
     * @return The minimal String representation of this class, as per
     * java.lang.Object.
     */
    @Override
    public String toString() {
        return getClass().getName() + "@" + Integer.toHexString(hashCode());
    }
}