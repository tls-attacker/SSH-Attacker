/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.OpenQuantumSafeKemNames;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPQKemPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPQKemPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OpenQuantumSafeKem extends KeyEncapsulation {
    private static final Logger LOGGER = LogManager.getLogger();
    private org.openquantumsafe.KeyEncapsulation kem;
    private CustomKeyPair<CustomPQKemPrivateKey, CustomPQKemPublicKey> localKeyPair;
    private CustomPQKemPublicKey remotePublicKey;
    private byte[] encryptedSharedSecret;
    private OpenQuantumSafeKemNames kemName;

    public OpenQuantumSafeKem(OpenQuantumSafeKemNames kemName) {
        if (kemName == OpenQuantumSafeKemNames.SNTRUP4591761) {
            throw new IllegalArgumentException(
                    OpenQuantumSafeKemNames.SNTRUP4591761.getName()
                            + " not supported by openquantumsafe.");
        }
        this.kem = new org.openquantumsafe.KeyEncapsulation(kemName.getName());
        this.kemName = kemName;
    }

    @Override
    public CustomKeyPair<CustomPQKemPrivateKey, CustomPQKemPublicKey> getLocalKeyPair() {
        return this.localKeyPair;
    }

    @Override
    public void setRemotePublicKey(byte[] remotePublicKeyBytes) {
        this.remotePublicKey = new CustomPQKemPublicKey(remotePublicKeyBytes, kemName);
    }

    @Override
    public void generateLocalKeyPair() {
        kem.generate_keypair();
        CustomPQKemPrivateKey privKey = new CustomPQKemPrivateKey(kem.export_secret_key(), kemName);
        CustomPQKemPublicKey pubKey = new CustomPQKemPublicKey(kem.export_public_key(), kemName);
        this.localKeyPair =
                new CustomKeyPair<CustomPQKemPrivateKey, CustomPQKemPublicKey>(privKey, pubKey);
    }

    @Override
    public void generateSharedSecret() {
        // Do nothing since the shared secret gets automatically created during the
        // encapsulation
    }

    @Override
    public byte[] encryptSharedSecret() {
        try {
            if (remotePublicKey == null) {
                LOGGER.warn("A Remote Key is not available, use a zero key instead.");
                setRemotePublicKey(new byte[CryptoConstants.SNTRUP761_PUBLIC_KEY_SIZE]);
            }
            org.openquantumsafe.Pair<byte[], byte[]> encapsulation =
                    kem.encap_secret(remotePublicKey.getEncoded());
            this.sharedSecret = new BigInteger(encapsulation.getRight());
            this.encryptedSharedSecret = encapsulation.getLeft();
            return encapsulation.getLeft();
        } catch (RuntimeException e) {
            LOGGER.error("Unexpected exception occured while encrypting the shared secret");
            LOGGER.debug(e);
        }
        return new byte[0];
    }

    @Override
    public void decryptSharedSecret(byte[] encryptedSharedSecret) throws CryptoException {
        try {
            this.sharedSecret = new BigInteger(kem.decap_secret(encryptedSharedSecret));
            this.encryptedSharedSecret = encryptedSharedSecret;
            LOGGER.info(
                    "SharedSecret Encapsulation = "
                            + ArrayConverter.bytesToRawHexString(
                                    ArrayConverter.bigIntegerToByteArray(sharedSecret)));
        } catch (RuntimeException e) {
            throw new CryptoException(
                    "Unexpected exception occured while decrypting the shared secret: " + e);
        }
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes) {
        throw new NotImplementedException(
                "Updateing localf Key Pairs not supported, use generateLocalKeys instead");
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        throw new NotImplementedException(
                "Updateing local Key Pairs not supported, use generateLocalKeys instead");
    }

    @Override
    public CustomPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    @Override
    public void setSharedSecret(byte[] sharedSecretBytes) {
        sharedSecret = new BigInteger(sharedSecretBytes);
    }

    @Override
    public void setEncryptedSharedSecret(byte[] encryptedSharedSecret) {
        this.encryptedSharedSecret = encryptedSharedSecret;
    }

    @Override
    public byte[] getEncryptedSharedSecret() {
        return encryptedSharedSecret;
    }

    @Override
    public void decryptSharedSecret() throws CryptoException {
        decryptSharedSecret(encryptedSharedSecret);
    }
}
