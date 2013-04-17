package be.crydust.aesencrypter;

import java.nio.file.Path;
import java.nio.file.Paths;

public class App {

    private static final int MIN_PASSWORD_LENGTH = 3;

    public static void main(String[] args) throws AESException {
        int argc = args.length;
        Path in = null;
        Path out = null;
        boolean encrypt = false;
        boolean decrypt = false;
        String password = null;
        boolean validInput = false;

        for (int i = 0; i < argc; i++) {
            switch (args[i]) {
                case "-e":
                case "--enc":
                    encrypt = true;
                    break;
                case "-d":
                case "--dec":
                    decrypt = true;
                    break;
                case "-i":
                case "--in":
                    if (i < argc - 1) {
                        in = Paths.get(args[++i]);
                    }
                    break;
                case "-o":
                case "--out":
                    if (i < argc - 1) {
                        out = Paths.get(args[++i]);
                    }
                    break;
                case "-p":
                case "--password":
                    if (i < argc - 1) {
                        password = args[++i];
                    }
                    break;
                default:
            }
        }

        if (!(encrypt || decrypt)) {
            System.out.println("Choose encrypt or decrypt.");
        } else if (encrypt && decrypt) {
            System.out.println("Choose encrypt or decrypt, not both.");
        } else if (in == null) {
            System.out.println("No input given.");
        } else if (out == null) {
            System.out.println("No output given.");
        } else if (password == null) {
            System.out.println("No password given.");
        } else if (password.length() < MIN_PASSWORD_LENGTH) {
            System.out.println("Password too short.");
        } else if (!in.toFile().exists()) {
            System.out.println("Input doesn't exist.");
        } else if (!in.toFile().canRead()) {
            System.out.println("Input isn't readable.");
        } else if (out.toFile().exists()) {
            System.out.println("Output exists.");
        } else {
            validInput = true;
        }

        if (!validInput) {
            System.out.println(""
                    + "usage:\n"
                    + "java -jar AESEncrypter-0.1.one-jar.jar -e -p password -i plain.txt -o encrypted.aes\n"
                    + "java -jar AESEncrypter-0.1.one-jar.jar -d -p password -i encrypted.aes -o plain.txt");
        } else {
            if (encrypt) {
                System.out.printf("encrypt %s -> %s%n", in, out);
                AESEncrypter.encrypt(password, in, out);
            } else if (decrypt) {
                System.out.printf("decrypt %s -> %s%n", in, out);
                AESEncrypter.decrypt(password, in, out);
            }
        }

    }
}
