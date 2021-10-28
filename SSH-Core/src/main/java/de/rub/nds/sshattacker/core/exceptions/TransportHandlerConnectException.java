/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class TransportHandlerConnectException extends RuntimeException {

    public TransportHandlerConnectException() {}

    public TransportHandlerConnectException(String string) {
        super(string);
    }

    public TransportHandlerConnectException(String string, Throwable throwable) {
        super(string, throwable);
    }

    public TransportHandlerConnectException(Throwable throwable) {
        super(throwable);
    }

    public TransportHandlerConnectException(
            String string, Throwable throwable, boolean bln, boolean bln1) {
        super(string, throwable, bln, bln1);
    }
}
