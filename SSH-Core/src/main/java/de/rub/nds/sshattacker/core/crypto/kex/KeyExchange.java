/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;

public abstract class KeyExchange {

    private final KeyExchangeAlgorithm negotiatedKeyExchange;
    protected byte[] sharedSecret;

    KeyExchange(KeyExchangeAlgorithm negotiatedKeyExchange) {
        this.negotiatedKeyExchange = negotiatedKeyExchange;
    }

    public abstract void computeSharedSecret();

    public abstract KeyPair getLocalKeyPair();

    public abstract KeyPair getRemotePublicKey();

    public boolean isComplete() {
        return sharedSecret != null;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public abstract static class KeyPair {
        public abstract byte[] serializePrivateKey();

        public abstract byte[] serializePublicKey();
    }
}
