/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.sshattacker.core.crypto.keys.CustomKeyPair;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomSntrup761PrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomSntrup761PublicKey;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.Sntrup;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.SntrupKeyPair;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;

public class CustomSntrup761KeyExchange extends KeyEncapsulation implements HybridKeyExchangeEncapsulation {
    private static final Logger LOGGER = LogManager.getLogger();
    private Sntrup sntrup;
    private CustomKeyPair<CustomSntrup761PrivateKey, CustomSntrup761PublicKey> localKeyPair;
    private CustomSntrup761PublicKey remotePublicKey;
    private byte[] cyphertext;

    public CustomSntrup761KeyExchange() {
        this.sntrup = new Sntrup(SntrupParameterSet.KEM_SNTRUP_761);
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
        SntrupKeyPair keyPair = sntrup.keyGen();
        CustomSntrup761PrivateKey privK = new CustomSntrup761PrivateKey(keyPair.getPrivK().getPrivK());
        CustomSntrup761PublicKey pubK = new CustomSntrup761PublicKey(keyPair.getPubK().getPubK());
        this.localKeyPair = new CustomKeyPair<CustomSntrup761PrivateKey, CustomSntrup761PublicKey>(privK, pubK);
    }

    @Override
    public CustomKeyPair<? extends CustomPrivateKey, ? extends CustomPublicKey> getLocalKeyPair() {
        return this.localKeyPair;
    }

    @Override
    public void setRemotePublicKey(byte[] publicKeyBytes) {
        this.remotePublicKey = new CustomSntrup761PublicKey(publicKeyBytes);
    }

    @Override
    public CustomPublicKey getRemotePublicKey() {
        return this.remotePublicKey;
    }

    @Override
    public void setGenerateSharedSecret(byte[] sharedSecretBytes) {
        sharedSecret = new BigInteger(sharedSecretBytes);

    }

    @Override
    public void setEncapsulatedSecret(byte[] cyphertext) {
        this.cyphertext = cyphertext;

    }

    @Override
    public byte[] getEncapsulatedSecret() {
        return cyphertext;
    }

    @Override
    public void decryptSharedSecret() throws CryptoException {
        decryptSharedSecret(cyphertext);
    }

    @Override
    public void generateSharedSecret() {
        LOGGER.warn("The shared secret currently gets automatically created during encapsulation.");
    }

    @Override
    public byte[] encryptSharedSecret() {
        sntrup.encaps(this.remotePublicKey.getEncoded());
        this.sharedSecret = new BigInteger(sntrup.getSharedSecret());
        this.cyphertext = sntrup.getCyphertext();
        return this.cyphertext;
    }

    @Override
    public void decryptSharedSecret(byte[] cyphertext) throws CryptoException {
        this.sharedSecret = new BigInteger(sntrup.decaps(this.localKeyPair.getPrivate().getPrivateKey(), cyphertext));
        this.cyphertext = cyphertext;
    }

}
