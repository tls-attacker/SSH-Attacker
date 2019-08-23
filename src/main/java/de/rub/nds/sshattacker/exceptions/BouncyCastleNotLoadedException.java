package de.rub.nds.sshattacker.exceptions;

public class BouncyCastleNotLoadedException extends RuntimeException {

    public BouncyCastleNotLoadedException() {
        super();
    }

    public BouncyCastleNotLoadedException(String message) {
        super(message);
    }

    public BouncyCastleNotLoadedException(String message, Throwable cause) {
        super(message, cause);
    }
}
