/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

/** Can be thrown if an exception with an oracle occurs */
public class OracleException extends RuntimeException {

    public OracleException() {
        super();
    }

    public OracleException(String message) {
        super(message);
    }

    public OracleException(String message, Throwable cause) {
        super(message, cause);
    }
}
