package de.rub.nds.sshattacker.exceptions;

public class ContextHandlingException extends RuntimeException {

    public ContextHandlingException() {
        super();
    }

    public ContextHandlingException(String message) {
        super(message);
    }

    public ContextHandlingException(String message, Throwable cause) {
        super(message, cause);
    }
}
