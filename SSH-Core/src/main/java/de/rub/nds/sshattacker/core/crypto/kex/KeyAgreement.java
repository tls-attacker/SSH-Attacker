/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class KeyAgreement extends KeyExchange {

    protected KeyAgreement() {
        super();
    }

    public abstract void setRemotePublicKey(byte[] publicKeyBytes);

    public abstract void computeSharedSecret() throws CryptoException;

    public abstract void generateLocalKeyPair();

    public abstract void setLocalKeyPair(byte[] privateKeyBytes);

    public abstract void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes);

    public abstract CustomKeyPair<? extends PrivateKey, ? extends PublicKey> getLocalKeyPair();
}
