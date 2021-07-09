/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;

public abstract class KeyExchange {

    private KeyExchangeAlgorithm negotiatedKeyExchange;
    protected byte[] sharedSecret;

    KeyExchange(KeyExchangeAlgorithm negotiatedKeyExchange) {
        this.negotiatedKeyExchange = negotiatedKeyExchange;
    }

    public abstract void computeSharedSecret();

    public abstract KeyPair getLocalKeyPair();

    public abstract KeyPair getRemotePublicKey();

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public abstract static class KeyPair {
        public abstract byte[] serializePrivateKey();

        public abstract byte[] serializePublicKey();
    }
}
