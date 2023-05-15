/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class TransportHandlerConnectException extends RuntimeException {

    public TransportHandlerConnectException() {
        super();
    }

    public TransportHandlerConnectException(String message) {
        super(message);
    }

    public TransportHandlerConnectException(String message, Throwable cause) {
        super(message, cause);
    }

    public TransportHandlerConnectException(Throwable cause) {
        super(cause);
    }

    public TransportHandlerConnectException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
