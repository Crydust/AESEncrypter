package be.crydust.aesencrypter;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

public final class AESEncrypter {

    private static final String PLAIN_ENCODING = "UTF-8";
    private static final String ENCRYPTED_ENCODING = "ASCII";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final String AES = "AES";
    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final int ITERATION_COUNT_MIN = 1024;
    private static final int ITERATION_COUNT_MAX = 2048;
    private static final int KEY_LENGTH = 128;
    private final Cipher encrypter;
    private final Cipher decrypter;
    private final int iterationCount;
    private final int keyLength;
    private final byte[] salt;
    private final byte[] iv;

    public static boolean encrypt(String password, Path plain, Path encrypted)
            throws AESException {
        try (InputStream plainIn = new FileInputStream(plain.toFile());
                OutputStream encryptedOut = new FileOutputStream(
                encrypted.toFile(), false);) {
            encrypt(password, plainIn, encryptedOut);
            return true;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException |
                NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException |
                InvalidParameterSpecException | IOException ex) {
            throw new AESException("encrypt failed", ex);
        }
    }

    public static void decrypt(String password, Path encrypted, Path plain)
            throws AESException {
        try (InputStream encryptedIn = new FileInputStream(encrypted.toFile());
                OutputStream plainOut = new FileOutputStream(plain.toFile(), true);) {
            decrypt(password, encryptedIn, plainOut);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException |
                NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IOException ex) {
            throw new AESException("decrypt failed", ex);
        }
    }

    public static String encrypt(@Nonnull String password, @Nonnull String plaintext)
            throws AESException {
        String result = null;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InputStream bios = new ByteArrayInputStream(plaintext.getBytes(PLAIN_ENCODING));) {
            encrypt(password, bios, baos);
            result = baos.toString(ENCRYPTED_ENCODING);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException |
                NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException |
                InvalidParameterSpecException | IOException ex) {
            throw new AESException("encrypt failed", ex);
        }
        return result;
    }

    public static String decrypt(String password, String encryptedString)
            throws AESException {
        String result = null;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                InputStream bios = new ByteArrayInputStream(encryptedString.getBytes(ENCRYPTED_ENCODING));) {
            decrypt(password, bios, baos);
            result = baos.toString(PLAIN_ENCODING);

        } catch (NoSuchAlgorithmException | InvalidKeySpecException |
                NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IOException ex) {
            throw new AESException("decrypt failed", ex);
        }
        return result;
    }

    public Cipher getEncrypter() {
        return encrypter;
    }

    public Cipher getDecrypter() {
        return decrypter;
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
    private AESEncrypter(String password) throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException {
        Random random = new SecureRandom();

        this.iterationCount = nextIntInRange(ITERATION_COUNT_MIN,
                ITERATION_COUNT_MAX, random);
        this.keyLength = KEY_LENGTH;

        this.salt = new byte[8];
        random.nextBytes(this.salt);

        Key key = generateKey(password, this.salt, this.iterationCount,
                this.keyLength);

        this.encrypter = Cipher.getInstance(CIPHER_TRANSFORMATION);
        encrypter.init(Cipher.ENCRYPT_MODE, key);
        this.iv = encrypter.getParameters()
                .getParameterSpec(IvParameterSpec.class).getIV();

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
    private AESEncrypter(String password, byte[] salt, byte[] iv, int iterationCount, int keyLength)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException {
        this.salt = salt;
        this.iv = iv;
        this.iterationCount = iterationCount;
        this.keyLength = keyLength;

        Key key = generateKey(password, this.salt, this.iterationCount, this.keyLength);

        this.encrypter = null;

        this.decrypter = Cipher.getInstance(CIPHER_TRANSFORMATION);
        decrypter.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(this.iv));
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
    private static Key generateKey(String password, byte[] salt, int iterationCount, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), AES);
    }

    /**
     * Encrypts the plaintext stream to a stream with all necessary data to
     * decrypt it. Not including the password of course. The string contains
     * only ASCII compatible characters thanks to base64 encoding.
     *
     * <p>
     * the output string contains
     * <ol>
     * <li>4 bytes int iterationCount: usually something larger than 1000
     * <li>4 bytes int keyLength: usually 128, for compatibility reasons
     * <li>4 bytes int saltLength: usually 8
     * <li>saltLength bytes byte[] salt
     * <li>4 bytes int ivLength: usually 16
     * <li>ivLength bytes byte[] iv
     * <li>rest encrypted bytes
     * </ol>
     * <p>
     * ints are in big endian order
     *
     * @param password
     * @param plain
     * @param encrypted
     */
    private static void encrypt(String password, InputStream plain, OutputStream encrypted)
            throws NoSuchAlgorithmException, InvalidKeySpecException,
            NoSuchPaddingException, InvalidKeyException,
            InvalidParameterSpecException, InvalidAlgorithmParameterException,
            IOException {
        try (OutputStream encryptedOut = new Base64OutputStream(new BufferedOutputStream(encrypted));
                DataOutputStream encDataOutputStream = new DataOutputStream(encryptedOut);
                InputStream plainIn = new BufferedInputStream(plain);) {
            AESEncrypter aes = new AESEncrypter(password);
            encDataOutputStream.writeInt(aes.iterationCount);
            encDataOutputStream.writeInt(aes.keyLength);
            encDataOutputStream.writeInt(aes.salt.length);
            encDataOutputStream.write(aes.salt);
            encDataOutputStream.writeInt(aes.iv.length);
            encDataOutputStream.write(aes.iv);
            applyCypher(aes.encrypter, plainIn, encryptedOut);
        }
    }

    public static void decrypt(String password, InputStream encrypted, OutputStream plain)
            throws IOException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, AESException {
        try (InputStream encryptedIn = new Base64InputStream(new BufferedInputStream(encrypted));
                DataInputStream encDataInputStream = new DataInputStream(encryptedIn);
                OutputStream plainOut = new BufferedOutputStream(plain);) {
            int iterationCount = encDataInputStream.readInt();
            int keyLength = encDataInputStream.readInt();
            int saltLength = encDataInputStream.readInt();
            byte[] salt = new byte[saltLength];
            if (encDataInputStream.read(salt) != saltLength) {
                throw new AESException("salt not readable");
            }
            int ivLength = encDataInputStream.readInt();
            byte[] iv = new byte[ivLength];
            if (encDataInputStream.read(iv) != ivLength) {
                throw new AESException("iv not readable");
            }
            AESEncrypter aes = new AESEncrypter(password, salt, iv,
                    iterationCount, keyLength);
            applyCypher(aes.decrypter, encryptedIn, plainOut);
        }
    }

    private static void applyCypher(Cipher cipher, InputStream in, OutputStream out)
            throws FileNotFoundException, IOException {
        try (CipherInputStream ciphecrInputStream = new CipherInputStream(in, cipher)) {
            byte[] buffer = new byte[4096];
            int nread;
            while ((nread = ciphecrInputStream.read(buffer)) != -1) {
                out.write(buffer, 0, nread);
            }
        }
    }

    private static int nextIntInRange(int min, int max, Random random) {
        return random.nextInt(max - min + 1) + min;
    }
}
