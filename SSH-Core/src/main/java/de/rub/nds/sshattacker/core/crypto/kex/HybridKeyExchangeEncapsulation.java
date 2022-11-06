/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;

public interface HybridKeyExchangeEncapsulation extends HybridKeyExchangeInterface {

    public abstract void generateSharedSecret();

    public abstract void setGenerateSharedSecret(byte[] sharedSecretBytes);

    public abstract byte[] encryptSharedSecret();

    public abstract void setEncapsulatedSecret(byte[] encryptedSharedSecret);

    public abstract byte[] getEncapsulatedSecret();

    public abstract void decryptSharedSecret() throws CryptoException;
}
