/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.cipher;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.util.Arrays;

import javax.crypto.AEADBadTagException;

class ChaCha20Poly1305Cipher extends AbstractCipher {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int TAG_LENGTH = 16;

    private final byte[] key;

    private final ChaChaEngine cipher;
    private final Poly1305 mac;

    ChaCha20Poly1305Cipher(byte[] key) {
        super();
        this.key = key;
        cipher = new ChaChaEngine();
        mac = new Poly1305();
    }

    @Override
    public byte[] encrypt(byte[] plainData) {
        throw new UnsupportedOperationException(
                "ChaCha20Poly1305 can only be used as an AEAD cipher!");
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv) {
        throw new UnsupportedOperationException(
                "ChaCha20Poly1305 can only be used as an AEAD cipher!");
    }

    @Override
    public byte[] encrypt(byte[] plainData, byte[] iv, byte[] additionalAuthenticatedData) {
        // Initialization
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        initMac();
        byte[] ciphertext = new byte[getOutputSize(true, plainData.length)];
        // Encryption
        cipher.processBytes(plainData, 0, plainData.length, ciphertext, 0);
        // MAC generation
        byte[] macInput =
                ArrayConverter.concatenate(
                        additionalAuthenticatedData, ciphertext, plainData.length);
        mac.update(macInput, 0, macInput.length);
        mac.doFinal(ciphertext, plainData.length);
        return ciphertext;
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) {
        throw new UnsupportedOperationException(
                "ChaCha20Poly1305 can only be used as an AEAD cipher!");
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv) {
        throw new UnsupportedOperationException(
                "ChaCha20Poly1305 can only be used as an AEAD cipher!");
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] iv, byte[] additionalAuthenticatedData)
            throws AEADBadTagException {
        // Initialization
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        initMac();
        byte[] plaintext = new byte[getOutputSize(false, encryptedData.length)];
        int ctLength = encryptedData.length - TAG_LENGTH;
        // MAC verification
        byte[] calculatedMac = new byte[TAG_LENGTH];
        byte[] macInput =
                ArrayConverter.concatenate(additionalAuthenticatedData, encryptedData, ctLength);
        mac.update(macInput, 0, macInput.length);
        mac.doFinal(calculatedMac, 0);
        byte[] receivedMac = Arrays.copyOfRange(encryptedData, ctLength, encryptedData.length);
        if (!Arrays.equals(calculatedMac, receivedMac)) {
            LOGGER.warn("MAC verification failed");
            throw new AEADBadTagException("Poly1305 MAC verification failed");
        }
        // Decryption
        cipher.processBytes(encryptedData, 0, ctLength, plaintext, 0);
        return plaintext;
    }

    private void initMac() {
        byte[] firstBlock = new byte[64];
        cipher.processBytes(firstBlock, 0, 64, firstBlock, 0);
        mac.init(new KeyParameter(firstBlock, 0, 32));
    }

    private static int getOutputSize(boolean isEncrypting, int inputLength) {
        return isEncrypting ? inputLength + TAG_LENGTH : inputLength - TAG_LENGTH;
    }

    @Override
    public EncryptionAlgorithm getAlgorithm() {
        return EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM;
    }
}
