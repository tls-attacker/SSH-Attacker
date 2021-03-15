package de.rub.nds.sshattacker.exceptions;

/**
 * Thrown when problems by in the SSH workflow appear.
 */
public class WorkflowExecutionException extends RuntimeException {

    public WorkflowExecutionException() {
        super();
    }

    public WorkflowExecutionException(String message) {
        super(message);
    }

    public WorkflowExecutionException(String message, Throwable t) {
        super(message, t);
    }
}
