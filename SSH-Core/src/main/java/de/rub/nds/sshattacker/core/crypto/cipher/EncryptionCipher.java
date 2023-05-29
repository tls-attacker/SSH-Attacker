/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.exceptions.CryptoException;

/** */
public interface EncryptionCipher {

    public int getBlocksize();

    public byte[] encrypt(byte[] someBytes) throws CryptoException;

    public byte[] encrypt(byte[] iv, byte[] someBytes) throws CryptoException;

    public byte[] encrypt(byte[] iv, int tagLength, byte[] someBytes) throws CryptoException;

    public byte[] encrypt(
            byte[] iv, int tagLength, byte[] additionAuthenticatedData, byte[] someBytes)
            throws CryptoException;

    public byte[] getIv();

    public void setIv(byte[] iv);

    DecryptionCipher getDecryptionCipher();
}
