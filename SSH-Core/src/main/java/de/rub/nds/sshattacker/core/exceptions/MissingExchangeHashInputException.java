/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class MissingExchangeHashInputException extends RuntimeException {

    public MissingExchangeHashInputException() {
        super();
    }

    public MissingExchangeHashInputException(String message) {
        super(message);
    }

    public MissingExchangeHashInputException(String message, Throwable cause) {
        super(message, cause);
    }

    public MissingExchangeHashInputException(Throwable cause) {
        super(cause);
    }

    public MissingExchangeHashInputException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
