/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import java.security.SecureRandom;

public abstract class KeyExchange {

    protected final SecureRandom random;

    protected KeyExchange() {
        this.random = new SecureRandom();
    }
}
