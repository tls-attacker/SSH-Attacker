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

public abstract class KeyEncapsulation extends KeyExchange {

    protected KeyEncapsulation() {
        super();
    }

    public abstract void setLocalKeyPair(byte[] privateKeyBytes);

    public abstract void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes);

    public abstract void generateLocalKeyPair();

    public abstract CustomKeyPair<? extends CustomPrivateKey, ? extends CustomPublicKey>
            getLocalKeyPair();

    public abstract CustomPublicKey getRemotePublicKey();

    public abstract void setRemotePublicKey(byte[] remotPublicKeyBytes);

    public abstract void setSharedSecret(byte[] sharedSecretBytes);

    public abstract void generateSharedSecret();

    public abstract void setEncapsulatedSecret(byte[] encryptedSharedSecret);

    public abstract byte[] getEncapsulatedSecret();

    public abstract byte[] encryptSharedSecret();

    public abstract void decryptSharedSecret() throws CryptoException;

    public abstract void decryptSharedSecret(byte[] encryptedSharedSecret) throws CryptoException;
}
