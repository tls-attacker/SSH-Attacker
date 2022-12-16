/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;

class NoneCipher extends AbstractCipher {

    public NoneCipher() {}

    @Override
    public byte[] encrypt(byte[] plainData) {
        return plainData;
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv) {
        return plainData;
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv, byte[] additionalEncryptedData) {
        return plainData;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) {
        return encryptedData;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv) {
        return encryptedData;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv, byte[] additionalAuthenticatedData) {
        return encryptedData;
    }

    @Override
    public EncryptionAlgorithm getAlgorithm() {
        return EncryptionAlgorithm.NONE;
    }
}
