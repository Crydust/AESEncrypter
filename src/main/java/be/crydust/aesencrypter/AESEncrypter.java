package be.crydust.aesencrypter;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Random;
import javax.annotation.Nonnull;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

public final class AESEncrypter {

    private static final int INT_LENGTH = 4;
    private static final String CHARACTER_ENCODING = "UTF-8";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String AES = "AES";
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
    //private static final int ITERATION_COUNT = 65536;
    private static final int ITERATION_COUNT_MIN = 1024;
    private static final int ITERATION_COUNT_MAX = 2048;
    private static final int KEY_LENGTH = 128;
    private final Cipher encrypter;
    private final Cipher decrypter;
    private final int iterationCount;
    private final int keyLength;
    private final byte[] salt;
    private final byte[] iv;

    public static boolean encrypt(String password, Path plain, Path encrypted) {
        try (
                OutputStream encryptedOut = new Base64OutputStream(new BufferedOutputStream(new FileOutputStream(encrypted.toFile(), false)));
                DataOutputStream encDataOutputStream = new DataOutputStream(encryptedOut);
                InputStream plainIn = new BufferedInputStream(new FileInputStream(plain.toFile()));) {
            AESEncrypter aes;
            try {
                aes = new AESEncrypter(password);
                encDataOutputStream.writeInt(aes.iterationCount);
                encDataOutputStream.writeInt(aes.keyLength);
                encDataOutputStream.writeInt(aes.salt.length);
                encDataOutputStream.write(aes.salt);
                encDataOutputStream.writeInt(aes.iv.length);
                encDataOutputStream.write(aes.iv);
                applyCypher(plainIn, aes.encrypter, encryptedOut);
                return true;
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidParameterSpecException | InvalidAlgorithmParameterException ex) {
                // ignore
            }
        } catch (IOException ex) {
            // ignore
        }
        return false;
    }

    public static boolean decrypt(String password, Path encrypted, Path plain) {
        try (
                InputStream encryptedIn = new Base64InputStream(new BufferedInputStream(new FileInputStream(encrypted.toFile())));
                DataInputStream encDataInputStream = new DataInputStream(encryptedIn);
                OutputStream plainOut = new BufferedOutputStream(new FileOutputStream(plain.toFile(), true));) {
            int iterationCount = encDataInputStream.readInt();
            int keyLength = encDataInputStream.readInt();
            int saltLength = encDataInputStream.readInt();
            byte[] salt = new byte[saltLength];
            encDataInputStream.read(salt);
            int ivLength = encDataInputStream.readInt();
            byte[] iv = new byte[ivLength];
            encDataInputStream.read(iv);
            AESEncrypter aes = new AESEncrypter(password, salt, iv, iterationCount, keyLength);
            applyCypher(encryptedIn, aes.decrypter, plainOut);
            return true;
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException ex) {
            // ignore
        }
        return false;
    }

    private static void applyCypher(InputStream in, Cipher cipher, OutputStream out) throws FileNotFoundException, IOException {
        try (CipherInputStream ciphecrInputStream = new CipherInputStream(in, cipher)) {
            byte[] buffer = new byte[4096];
            int nread;
            while ((nread = ciphecrInputStream.read(buffer)) != -1) {
                out.write(buffer, 0, nread);
            }
        }
    }

    private void encrypt(Path plain, Path enc) throws FileNotFoundException {
        //TODO
    }

    /**
     * Encrypts the plaintext string to a string with all necessary data to
     * decrypt it. Not including the password of course. The string contains
     * only ASCII compatible characters thanks to base64 encoding.
     *
     * <p>the output string contains
     * <ol>
     * <li>4 bytes int iterationCount: usually something larger than 1000
     * <li>4 bytes int keyLength: usually 128, for compatibility reasons
     * <li>4 bytes int saltLength: usually 8
     * <li>saltLength bytes byte[] salt
     * <li>4 bytes int ivLength: usually 16
     * <li>ivLength bytes byte[] iv
     * <li>rest encrypted bytes
     * </ol>
     * <p>ints are in big endian order
     *
     * @param password
     * @param plaintext
     * @return
     */
    public static String encrypt(@Nonnull String password, @Nonnull String plaintext) {
        String result = null;
        try {
            AESEncrypter aes = new AESEncrypter(password);
            return aes.encrypt(plaintext);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidParameterSpecException | InvalidAlgorithmParameterException e) {
            // ignore
        }
        return result;
    }

    private String encrypt(@Nonnull String plaintext) {
        String result = null;
        try {
            byte[] encrypted = encryptToByteArray(plaintext);
            byte[] bytes = new byte[0
                    + INT_LENGTH
                    + INT_LENGTH
                    + INT_LENGTH + salt.length
                    + INT_LENGTH + iv.length
                    + encrypted.length];
            ByteBuffer.wrap(bytes)
                    .order(ByteOrder.BIG_ENDIAN)
                    .putInt(iterationCount)
                    .putInt(keyLength)
                    .putInt(salt.length).put(salt)
                    .putInt(iv.length).put(iv)
                    .put(encrypted);
            result = Base64.encodeBase64String(bytes);
        } catch (IllegalBlockSizeException | UnsupportedEncodingException | BadPaddingException e) {
            // ignore
        }
        return result;
    }

    public static String decrypt(String password, String encryptedString) {
        String result = null;
        try {
            byte[] bytes = Base64.decodeBase64(encryptedString);
            ByteBuffer bb = ByteBuffer.wrap(bytes);
            bb.order(ByteOrder.BIG_ENDIAN);
            int iterationCount = bb.getInt();
            int keyLength = bb.getInt();
            int saltLength = bb.getInt();
            byte[] salt = new byte[saltLength];
            bb.get(salt);
            int ivLength = bb.getInt();
            byte[] iv = new byte[ivLength];
            bb.get(iv);
            int encryptedLength = bytes.length - bb.position();
            byte[] encrypted = new byte[encryptedLength];
            bb.get(encrypted);
            AESEncrypter aes = new AESEncrypter(password, salt, iv, iterationCount, keyLength);
            result = aes.decryptByteArray(encrypted);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException e) {
            // ignore
        }
        return result;
    }

    /*
     @SuppressWarnings("unused")
     private String decrypt(String encryptedString) {
     String result = null;
     try {
     byte[] bytes = Base64.decodeBase64(encryptedString);
     ByteBuffer bb = ByteBuffer.wrap(bytes);
     bb.order(ByteOrder.BIG_ENDIAN);
     int saltLength = bb.getInt(2 * INT_LENGTH);
     int ivLength = bb.getInt(3 * INT_LENGTH + saltLength);
     int encryptedPosition = 4 * INT_LENGTH + saltLength + ivLength;
     int encryptedLength = bytes.length - encryptedPosition;
     byte[] encrypted = new byte[encryptedLength];
     bb.position(encryptedPosition);
     bb.get(encrypted, 0, encryptedLength);
     result = decryptByteArray(encrypted);
     } catch (UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException e) {
     // ignore
     }
     return result;
     }
     */
    private static int nextIntInRange(int min, int max, Random random) {
        return random.nextInt(max - min + 1) + min;
    }

    /**
     * AESEncrypter that can encrypt and decrypt
     *
     * @param password
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     */
    private AESEncrypter(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        Random random = new SecureRandom();

        this.iterationCount = nextIntInRange(ITERATION_COUNT_MIN, ITERATION_COUNT_MAX, random);
        this.keyLength = KEY_LENGTH;

        this.salt = new byte[8];
        random.nextBytes(this.salt);

        Key key = generateKey(password, this.salt, this.iterationCount, this.keyLength);

        this.encrypter = Cipher.getInstance(CIPHER_TRANSFORMATION);
        encrypter.init(Cipher.ENCRYPT_MODE, key);
        this.iv = encrypter.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

        this.decrypter = Cipher.getInstance(CIPHER_TRANSFORMATION);
        decrypter.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(this.iv));
    }

    /**
     * AESEncrypter that can decrypt only
     *
     * @param password
     * @param salt
     * @param iv
     * @param iterationCount
     * @param keyLength
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    private AESEncrypter(String password, byte[] salt, byte[] iv, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        this.salt = salt;
        this.iv = iv;
        this.iterationCount = iterationCount;
        this.keyLength = keyLength;

        Key key = generateKey(password, this.salt, this.iterationCount, this.keyLength);

        this.encrypter = null;

        this.decrypter = Cipher.getInstance(CIPHER_TRANSFORMATION);
        decrypter.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(this.iv));
    }

    private byte[] encryptToByteArray(String plaintext) throws IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException {
        if (encrypter == null) {
            throw new UnsupportedOperationException("encrypt doesn't work with a fixed iv, that would be insecure");
        }
        return encrypter.doFinal(plaintext.getBytes(CHARACTER_ENCODING));
    }

    private String decryptByteArray(byte[] encrypted) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        return new String(decrypter.doFinal(encrypted), CHARACTER_ENCODING);
    }

    /**
     * generates the secret Key used for both encryption and decryption
     *
     * @param password
     * @param salt
     * @param iterationCount
     * @param keyLength
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static Key generateKey(String password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), AES);
    }
}
