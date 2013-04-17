package be.crydust.aesencrypter;

public class AESException extends Exception {
    
    public AESException(String message) {
        super(message);
    }

    public AESException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
