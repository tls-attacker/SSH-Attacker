/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.crypto.keys.CustomFrodoKem1344PrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomFrodoKem1344PublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class FrodoKem1344KeyExchange extends KeyEncapsulation {
    private static final Logger LOGGER = LogManager.getLogger();
    private org.openquantumsafe.KeyEncapsulation frodokem;
    private CustomKeyPair<CustomFrodoKem1344PrivateKey, CustomFrodoKem1344PublicKey> localKeyPair;
    private CustomFrodoKem1344PublicKey remotePublicKey;
    private byte[] encryptedSharedSecret;

    public FrodoKem1344KeyExchange() {
        this.frodokem = new org.openquantumsafe.KeyEncapsulation("FrodoKEM-1344-SHAKE");
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes) {
        LOGGER.warn("Updateing local Key Pairs not supported, use generateLocalKeys instead");
    }

    @Override
    public void setLocalKeyPair(byte[] privateKeyBytes, byte[] publicKeyBytes) {
        LOGGER.warn("Updateing local Key Pairs not supported, use generateLocalKeys instead");
    }

    @Override
    public void generateLocalKeyPair() {
        frodokem.generate_keypair();
        CustomFrodoKem1344PrivateKey privateKey =
                new CustomFrodoKem1344PrivateKey(frodokem.export_secret_key());
        CustomFrodoKem1344PublicKey publicKey =
                new CustomFrodoKem1344PublicKey(frodokem.export_public_key());
        this.localKeyPair =
                new CustomKeyPair<CustomFrodoKem1344PrivateKey, CustomFrodoKem1344PublicKey>(
                        privateKey, publicKey);
    }

    @Override
    public CustomKeyPair<? extends CustomPrivateKey, ? extends CustomPublicKey> getLocalKeyPair() {
        return localKeyPair;
    }

    @Override
    public void setRemotePublicKey(byte[] publicKeyBytes) {
        this.remotePublicKey = new CustomFrodoKem1344PublicKey(publicKeyBytes);
    }

    @Override
    public CustomPublicKey getRemotePublicKey() {
        return this.remotePublicKey;
    }

    @Override
    public void generateSharedSecret() {
        // Do nothing since the shared secret gets automatically created during the
        // encapsulation
    }

    @Override
    public byte[] encryptSharedSecret() {
        try {
            org.openquantumsafe.Pair<byte[], byte[]> encapsulation =
                    frodokem.encap_secret(remotePublicKey.getEncoded());
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
    public void decryptSharedSecret() throws CryptoException {
        decryptSharedSecret(encryptedSharedSecret);
    }

    @Override
    public void decryptSharedSecret(byte[] encryptedSharedSecret) throws CryptoException {
        try {
            this.sharedSecret = new BigInteger(frodokem.decap_secret(encryptedSharedSecret));
            this.encryptedSharedSecret = encryptedSharedSecret;
        } catch (RuntimeException e) {
            LOGGER.error("Unexpected exception occured while decrypting the shared secret");
            LOGGER.debug(e);
        }
    }

    @Override
    public void setSharedSecret(byte[] sharedSecretBytes) {
        new BigInteger(sharedSecretBytes);
    }

    @Override
    public void setEncryptedSharedSecret(byte[] encryptedSharedSecret) {
        this.encryptedSharedSecret = encryptedSharedSecret;
    }

    @Override
    public byte[] getEncryptedSharedSecret() {
        return this.encryptedSharedSecret;
    }
}
