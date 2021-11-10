/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;

public class NoneCipher implements EncryptionCipher, DecryptionCipher {

    public NoneCipher() {}

    @Override
    public byte[] encrypt(byte[] data) {
        return data;
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] additionalEncryptedData) {
        return data;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) {
        return encryptedData;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] additionalEncryptedData) {
        return encryptedData;
    }

    @Override
    public EncryptionAlgorithm getAlgorithm() {
        return EncryptionAlgorithm.NONE;
    }

    @Override
    public byte[] getIV() {
        return null;
    }

    @Override
    public void setIV(byte[] iv) {}
}
