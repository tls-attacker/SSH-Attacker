/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;

import javax.crypto.AEADBadTagException;

public abstract class AbstractCipher {

    public abstract byte[] encrypt(byte[] plainData) throws CryptoException;

    public abstract byte[] encrypt(byte[] plainData, byte[] iv) throws CryptoException;

    public abstract byte[] encrypt(byte[] plainData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException;

    public abstract byte[] decrypt(byte[] encryptedData) throws CryptoException;

    public abstract byte[] decrypt(byte[] encryptedData, byte[] iv) throws CryptoException;

    public abstract byte[] decrypt(
            byte[] encryptedData, byte[] iv, byte[] additionalAuthenticatedData)
            throws CryptoException, AEADBadTagException;

    public abstract EncryptionAlgorithm getAlgorithm();
}
