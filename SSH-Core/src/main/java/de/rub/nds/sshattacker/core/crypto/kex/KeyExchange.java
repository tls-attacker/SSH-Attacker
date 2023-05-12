/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import java.security.SecureRandom;

@SuppressWarnings("AbstractClassWithoutAbstractMethods")
public abstract class KeyExchange {

    protected final SecureRandom random;
    protected byte[] sharedSecret;

    protected KeyExchange() {
        super();
        random = new SecureRandom();
    }

    public boolean isComplete() {
        return sharedSecret != null;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }
}
