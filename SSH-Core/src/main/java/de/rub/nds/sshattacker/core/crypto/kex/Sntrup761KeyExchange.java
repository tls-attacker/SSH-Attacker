/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomSntrup761PrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomSntrup761PublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761KeyExchange extends KeyEncapsulation {

    private static final Logger LOGGER = LogManager.getLogger();
    private org.openquantumsafe.KeyEncapsulation sntrup;
    private CustomKeyPair<CustomSntrup761PrivateKey, CustomSntrup761PublicKey> localKeyPair;
    private CustomSntrup761PublicKey remotePublicKey;
    private byte[] encryptedSharedSecret;

    public Sntrup761KeyExchange() {
        this.sntrup = new org.openquantumsafe.KeyEncapsulation("sntrup761");
    }

    public CustomKeyPair<CustomSntrup761PrivateKey, CustomSntrup761PublicKey> getLocalKeyPair() {
        return this.localKeyPair;
    }

    public void setRemotePublicKey(byte[] serializedPublicKey) {
        this.remotePublicKey = new CustomSntrup761PublicKey(serializedPublicKey);
    }

    public void generateLocalKeyPair() {
        sntrup.generate_keypair();
        CustomSntrup761PrivateKey privKey =
                new CustomSntrup761PrivateKey(sntrup.export_secret_key());
        CustomSntrup761PublicKey pubKey = new CustomSntrup761PublicKey(sntrup.export_public_key());
        this.localKeyPair =
                new CustomKeyPair<CustomSntrup761PrivateKey, CustomSntrup761PublicKey>(
                        privKey, pubKey);
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
                    sntrup.encap_secret(remotePublicKey.getEncoded());
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
            this.sharedSecret = new BigInteger(sntrup.decap_secret(encryptedSharedSecret));
            this.encryptedSharedSecret = encryptedSharedSecret;
        } catch (RuntimeException e) {
            LOGGER.error("Unexpected exception occured while decrypting the shared secret");
            LOGGER.debug(e);
        }
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
    public CustomPublicKey getRemotePublicKey() {
        return remotePublicKey;
    }

    @Override
    public void setSharedSecret(byte[] sharedSecretBytes) {
        sharedSecret = new BigInteger(sharedSecretBytes);
    }

    @Override
    public void setEncapsulatedSecret(byte[] encryptedSharedSecret) {
        this.encryptedSharedSecret = encryptedSharedSecret;
    }

    @Override
    public byte[] getEncapsulatedSecret() {
        return encryptedSharedSecret;
    }

    @Override
    public void decryptSharedSecret() throws CryptoException {
        decryptSharedSecret(encryptedSharedSecret);
    }
}
