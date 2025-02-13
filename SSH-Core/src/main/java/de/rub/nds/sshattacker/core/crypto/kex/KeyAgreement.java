/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;

public abstract class KeyAgreement<PRIVATE extends CustomPrivateKey, PUBLIC extends CustomPublicKey>
        extends KeyExchange {

    protected CustomKeyPair<PRIVATE, PUBLIC> localKeyPair;
    protected PUBLIC remotePublicKey;

    protected KeyAgreement() {
        super();
    }

    public CustomKeyPair<PRIVATE, PUBLIC> getLocalKeyPair() {
        return localKeyPair;
    }

    public void setLocalKeyPair(CustomKeyPair<PRIVATE, PUBLIC> localKeyPair) {
        this.localKeyPair = localKeyPair;
    }

    public abstract void setLocalKeyPair(byte[] encodedPrivateKey);

    public abstract void setLocalKeyPair(byte[] encodedPrivateKey, byte[] encodedPublicKey);

    public PUBLIC getRemotePublicKey() {
        return remotePublicKey;
    }

    public void setRemotePublicKey(PUBLIC remotePublicKey) {
        this.remotePublicKey = remotePublicKey;
    }

    public abstract void setRemotePublicKey(byte[] encodedPublicKey);

    public abstract void computeSharedSecret() throws CryptoException;
}
