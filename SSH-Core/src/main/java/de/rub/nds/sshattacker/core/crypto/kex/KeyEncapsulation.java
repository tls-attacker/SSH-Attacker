/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.security.PublicKey;

public abstract class KeyEncapsulation<PUBLIC extends PublicKey> extends KeyExchange {

    protected PUBLIC publicKey;
    protected byte[] encapsulation;

    protected KeyEncapsulation() {
        super();
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PUBLIC publicKey) {
        this.publicKey = publicKey;
    }

    public abstract void encapsulate() throws CryptoException;

    public byte[] getEncapsulation() {
        return encapsulation;
    }

    public void setEncapsulation(byte[] encapsulation) {
        this.encapsulation = encapsulation;
    }

    public abstract void decapsulate() throws CryptoException;
}
