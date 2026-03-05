/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.exceptions;

public class OpenQuantumSafeConfigurationException extends ConfigurationException {

    public OpenQuantumSafeConfigurationException() {
        super();
    }

    public OpenQuantumSafeConfigurationException(String message) {
        super(message);
    }

    public OpenQuantumSafeConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
