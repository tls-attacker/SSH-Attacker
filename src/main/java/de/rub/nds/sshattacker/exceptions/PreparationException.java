package de.rub.nds.sshattacker.exceptions;

public class PreparationException extends RuntimeException {

    public PreparationException() {
    }

    public PreparationException(String message) {
        super(message);
    }

    public PreparationException(String message, Throwable cause) {
        super(message, cause);
    }
}