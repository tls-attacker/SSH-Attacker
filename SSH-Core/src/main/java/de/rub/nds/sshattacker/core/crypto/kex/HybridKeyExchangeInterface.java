/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import java.math.BigInteger;

import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;

public interface HybridKeyExchangeInterface {
    
    public abstract void setLocalKeyPair(byte[] privateKeyBytes);
    
    public abstract void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes);

    public abstract void generateLocalKeyPair();

    public abstract CustomKeyPair<? extends CustomPrivateKey, ? extends CustomPublicKey> getLocalKeyPair();

    public abstract void setRemotePublicKey(byte[] publicKeyBytes);

    public abstract CustomPublicKey getRemotePublicKey(); 

    public abstract BigInteger getSharedSecret();
}
