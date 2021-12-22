/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class MissingChannelException extends RuntimeException {

    public MissingChannelException() {
        super();
    }

    public MissingChannelException(String message) {
        super(message);
    }

    public MissingChannelException(String message, Throwable cause) {
        super(message, cause);
    }
}
