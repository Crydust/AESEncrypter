package be.crydust.aesencrypter;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;

public class AESEncrypterTest {

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testEncryptAndDecryptSimpleStrings() throws UnsupportedEncodingException {
        String password, plaintext;
        password = "";
        plaintext = "";
        checkEncryptAndDecryptSimpleStrings(password, plaintext);
        password = "a";
        plaintext = "";
        checkEncryptAndDecryptSimpleStrings(password, plaintext);
        password = "";
        plaintext = "a";
        checkEncryptAndDecryptSimpleStrings(password, plaintext);
        password = "a";
        plaintext = "a";
        checkEncryptAndDecryptSimpleStrings(password, plaintext);
    }

    private void checkEncryptAndDecryptSimpleStrings(String password, String plaintext) throws UnsupportedEncodingException {
        String encrypted1 = AESEncrypter.encrypt(password, plaintext);
        String encrypted2 = AESEncrypter.encrypt(password, plaintext);

        assertNotNull(encrypted1);
        assertEquals(AESEncrypter.decrypt(password, encrypted1), plaintext);
        @SuppressWarnings({"unused", "MismatchedReadAndWriteOfArray"})
        byte[] dummy1 = encrypted1.getBytes("ASCII");

        assertNotNull(encrypted2);
        assertEquals(AESEncrypter.decrypt(password, encrypted2), plaintext);
        @SuppressWarnings({"unused", "MismatchedReadAndWriteOfArray"})
        byte[] dummy2 = encrypted2.getBytes("ASCII");

        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    public void testEncryptAndDecryptFiles() throws IOException {
        String encoding = "UTF-8";
        String plaintext = "Hello World";
        String password = "password";
        
        File plainFile = folder.newFile();
        File encryptedFile = folder.newFile();
        File decryptedFile = folder.newFile();

        Files.write(plainFile.toPath(), plaintext.getBytes(encoding));
        AESEncrypter.encrypt(password, plainFile.toPath(), encryptedFile.toPath());
        String encrypted = new String(Files.readAllBytes(encryptedFile.toPath()), encoding);
        System.out.printf("encrypted = %s%n", encrypted);
        AESEncrypter.decrypt(password, encryptedFile.toPath(), decryptedFile.toPath());
        String decrypted = new String(Files.readAllBytes(decryptedFile.toPath()), encoding);
        System.out.printf("decrypted = %s%n", decrypted);
        
        assertNotEquals(plaintext, encrypted);
        assertEquals(plaintext, decrypted);
    }
}