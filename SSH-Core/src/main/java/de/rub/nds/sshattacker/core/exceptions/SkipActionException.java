/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class SkipActionException extends RuntimeException {

    public SkipActionException() {
        super();
    }

    public SkipActionException(String message) {
        super(message);
    }

    public SkipActionException(String message, Throwable cause) {
        super(message, cause);
    }

    public SkipActionException(Throwable cause) {
        super(cause);
    }

    public SkipActionException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
