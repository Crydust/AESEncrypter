package be.crydust.aesencrypter;

public class AESRuntimeException extends RuntimeException {

    public AESRuntimeException(String message) {
        super(message);
    }

    public AESRuntimeException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
