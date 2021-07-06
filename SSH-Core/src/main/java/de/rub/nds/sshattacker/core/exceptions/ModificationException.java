/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

/**
 * Thrown when problems by modification application appear.
 */
public class ModificationException extends RuntimeException {

    public ModificationException() {
        super();
    }

    public ModificationException(String message) {
        super(message);
    }

    public ModificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
