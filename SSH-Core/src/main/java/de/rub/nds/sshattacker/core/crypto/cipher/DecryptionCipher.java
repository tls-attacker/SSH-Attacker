/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;

/** */
public interface DecryptionCipher {

    byte[] decrypt(byte[] encryptedData) throws CryptoException;

    byte[] decrypt(byte[] iv, byte[] additionalAuthenticatedData) throws CryptoException;

    EncryptionAlgorithm getAlgorithm();

    byte[] getIV();

    void setIV(byte[] iv) throws CryptoException;
}
