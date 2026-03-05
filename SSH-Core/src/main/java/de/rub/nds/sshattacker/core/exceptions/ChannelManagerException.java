/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class ChannelManagerException extends RuntimeException {

    public ChannelManagerException() {
        super();
    }

    public ChannelManagerException(String message) {
        super(message);
    }

    public ChannelManagerException(String message, Throwable cause) {
        super(message, cause);
    }
}
