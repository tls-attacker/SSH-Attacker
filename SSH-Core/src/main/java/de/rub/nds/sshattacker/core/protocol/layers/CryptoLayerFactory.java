/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.layers;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class CryptoLayerFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private CryptoLayerFactory() {
    }

    private static String getCipherTransformByAlgorithm(EncryptionAlgorithm encryptionAlgorithm) {
        switch (encryptionAlgorithm) {
            case AES128_CBC:
            case AES192_CBC:
            case AES256_CBC:
                return "AES/CBC/NoPadding";
            case AES128_CTR:
            case AES192_CTR:
            case AES256_CTR:
                return "AES/CTR/NoPadding";
                // TODO: Test ARCFOUR implementation (find a SSH implementation still using it)
            case ARCFOUR:
            case ARCFOUR128:
            case ARCFOUR256:
                return "ARCFOUR";
                // TODO: Test Blowfish implementation (find a SSH implementation still using it)
            case BLOWFISH_CBC:
                return "Blowfish/CBC/NoPadding";
            case BLOWFISH_CTR:
                return "Blowfish/CTR/NoPadding";
                // TODO: Test DES implementation (find a SSH implementation still using it)
            case DES_CBC:
                return "DES/CBC/NoPadding";
            case TRIPLE_DES_CBC:
                return "DESede/CBC/NoPadding";
                // TODO: Test 3DES CTR implementation (find a SSH implementation still using it)
            case TRIPLE_DES_CTR:
                return "DESede/CTR/NoPadding";
            default:
                LOGGER.fatal("The following cipher algorithm was negotiated, but is not yet implemented: "
                        + encryptionAlgorithm);
                throw new NotImplementedException("CryptoLayerFactory::getCipherTransformByAlgorithm");
        }
    }

    private static String getMacTransformByAlgorithm(MacAlgorithm macAlgorithm) {
        switch (macAlgorithm) {
            case HMAC_SHA1:
            case HMAC_SHA1_96:
            case HMAC_SHA1_ETM_OPENSSH_COM:
            case HMAC_SHA1_96_ETM_OPENSSH_COM:
                return "HmacSHA1";
            case HMAC_SHA2_256:
            case HMAC_SHA2_256_ETM_OPENSSH_COM:
                return "HmacSHA256";
            case HMAC_SHA2_512:
            case HMAC_SHA2_512_ETM_OPENSSH_COM:
                return "HmacSHA512";
            default:
                LOGGER.fatal("The following mac algorithm was negotiated, but is not yet implemented: " + macAlgorithm);
                throw new NotImplementedException("CryptoLayerFactory::getMacTransformByAlgorithm");
        }
    }

    private static AlgorithmParameterSpec getCipherParametersByAlgorithm(byte[] parameters,
            EncryptionAlgorithm encryptionAlgorithm) {
        switch (encryptionAlgorithm) {
            case AES128_CBC:
            case AES128_CTR:
            case AES192_CBC:
            case AES192_CTR:
            case AES256_CBC:
            case AES256_CTR:
            case BLOWFISH_CBC:
            case BLOWFISH_CTR:
            case DES_CBC:
            case TRIPLE_DES_CBC:
            case TRIPLE_DES_CTR:
                return new IvParameterSpec(parameters);
            case AEAD_AES_128_GCM:
            case AEAD_AES_256_GCM:
            case AES128_GCM_OPENSSH_COM:
            case AES256_GCM_OPENSSH_COM:
                return new GCMParameterSpec(MacAlgorithm.AEAD_AES_128_GCM.getOutputSize(), parameters);
            default:
                return null;
        }
    }

    public static CryptoLayer getCryptoLayer(boolean clientToServer, SshContext sshContext) {
        EncryptionAlgorithm encryptionAlgorithm = clientToServer ? sshContext.getCipherAlgorithmClientToServer()
                : sshContext.getCipherAlgorithmServerToClient();
        MacAlgorithm macAlgorithm = clientToServer ? sshContext.getMacAlgorithmClientToServer() : sshContext
                .getMacAlgorithmServerToClient();
        String cipherTransform = getCipherTransformByAlgorithm(encryptionAlgorithm);
        String macTransform = getMacTransformByAlgorithm(macAlgorithm);
        Key cipherKey = new SecretKeySpec(clientToServer ? sshContext.getEncryptionKeyClientToServer()
                : sshContext.getEncryptionKeyServerToClient(), cipherTransform);
        Key macKey = new SecretKeySpec(clientToServer ? sshContext.getIntegrityKeyClientToServer()
                : sshContext.getIntegrityKeyServerToClient(), macTransform);
        AlgorithmParameterSpec cipherParams = getCipherParametersByAlgorithm(
                clientToServer ? sshContext.getInitialIvClientToServer() : sshContext.getInitialIvServerToClient(),
                encryptionAlgorithm);

        LOGGER.info("Instantiating a new JCACryptoLayer with the following specifications:");
        LOGGER.info("Cipher: " + encryptionAlgorithm);
        LOGGER.info("Corresponding cipher transform: " + cipherTransform);
        LOGGER.info("MAC: " + macAlgorithm);
        LOGGER.info("Corresponding MAC transform: " + macTransform);

        return new JCACryptoLayer(encryptionAlgorithm, cipherTransform, cipherKey, cipherParams, macAlgorithm,
                macTransform, macKey, sshContext);
    }
}
