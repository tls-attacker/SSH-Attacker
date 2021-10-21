/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.layers;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;

public class JCACryptoLayer extends CryptoLayer {

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    private Mac mac;

    @SuppressWarnings("FieldCanBeLocal")
    private Mac verify;

    public JCACryptoLayer(
            EncryptionAlgorithm encryptionAlgorithm,
            String cipherTransform,
            Key cipherKey,
            AlgorithmParameterSpec cipherParams,
            MacAlgorithm macAlgorithm,
            String macTransform,
            Key macKey,
            SshContext context) {
        super(encryptionAlgorithm, macAlgorithm, context);
        initCiphers(cipherTransform, cipherKey, cipherParams);
        initMacs(macTransform, macKey);
    }

    private void initCiphers(
            String cipherTransform, Key cipherKey, AlgorithmParameterSpec cipherParams) {
        try {
            encryptCipher = Cipher.getInstance(cipherTransform);
            if (cipherParams != null) {
                encryptCipher.init(Cipher.ENCRYPT_MODE, cipherKey, cipherParams);
            } else {
                encryptCipher.init(Cipher.ENCRYPT_MODE, cipherKey);
            }
            decryptCipher = Cipher.getInstance(cipherTransform);
            if (cipherParams != null) {
                decryptCipher.init(Cipher.DECRYPT_MODE, cipherKey, cipherParams);
            } else {
                decryptCipher.init(Cipher.DECRYPT_MODE, cipherKey);
            }

        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Provider does not support this algorithm. " + e.getMessage());
        } catch (NoSuchPaddingException e) {
            LOGGER.warn("Provider does not support this padding. " + e.getMessage());
        } catch (InvalidKeyException e) {
            LOGGER.warn("Key does not correspond to used cipher. " + e.getMessage());
        } catch (InvalidAlgorithmParameterException e) {
            LOGGER.warn(e.getMessage());
        }
    }

    private void initMacs(String macTransform, Key macKey) {
        try {
            mac = Mac.getInstance(macTransform);
            mac.init(macKey);
            verify = Mac.getInstance(macTransform);
            mac.init(macKey);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("MAC algorithm is not supported. " + e.getMessage());
        } catch (InvalidKeyException e) {
            LOGGER.warn("Key is not suitable for this MAC. " + e.getMessage());
        }
    }

    @Override
    protected byte[] encrypt(byte[] plaintext) {
        return encryptCipher.update(plaintext);
    }

    @Override
    protected byte[] decrypt(byte[] ciphertext) {
        return decryptCipher.update(ciphertext);
    }

    @Override
    protected byte[] computeMAC(byte[] input) {
        return mac.doFinal(input);
    }

    @Override
    protected void verifyMAC(byte[] input, byte[] mac) {
        // TODO: Implement verifyMAC
        throw new NotImplementedException("JCACryptoLayer::verifyMAC");
    }
}
