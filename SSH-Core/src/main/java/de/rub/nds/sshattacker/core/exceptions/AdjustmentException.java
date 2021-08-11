/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class AdjustmentException extends RuntimeException {

    public AdjustmentException() {}

    public AdjustmentException(String message) {
        super(message);
    }

    public AdjustmentException(String message, Throwable cause) {
        super(message, cause);
    }

    public AdjustmentException(Throwable cause) {
        super(cause);
    }

    public AdjustmentException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
