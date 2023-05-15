/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.exception;

/**
 * This exception is thrown when the oracle is unstable, f.e., when a server can no longer be
 * connected to for some Reason
 */
public class OracleUnstableException extends RuntimeException {

    public OracleUnstableException(String message) {
        super(message);
    }
}
