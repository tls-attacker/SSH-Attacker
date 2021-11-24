/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.RsaPublicKey;
import java.math.BigInteger;

public class RsaKeyExchange extends KeyExchange {

    private RsaPublicKey publicKey;

    // HLEN in RFC 4432 (in bits)
    private int hashLength;

    public RsaKeyExchange() {}

    public RsaKeyExchange(RsaPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public void computeSharedSecret() {
        // Calculation of maximum number of bits taken from RFC 4432
        int maximumBits = (getModulusLengthInBits() - 2 * hashLength - 49);
        sharedSecret = new BigInteger(maximumBits, random);
    }

    public void setPublicKey(RsaPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public RsaPublicKey getPublicKey() {
        return publicKey;
    }

    public BigInteger getExponent() {
        return publicKey.getPublicExponent();
    }

    public BigInteger getModulus() {
        return publicKey.getModulus();
    }

    public int getHashLength() {
        return hashLength;
    }

    public void setHashLength(int hashLength) {
        this.hashLength = hashLength;
    }

    public void setHashLength(KeyExchangeAlgorithm keyExchangeAlgorithm) {
        switch (keyExchangeAlgorithm) {
            case RSA1024_SHA1:
                setHashLength(128);
                break;
            case RSA2048_SHA256:
                setHashLength(256);
                break;
            default:
                setHashLength(0);
                break;
        }
    }

    private int getModulusLengthInBits() {
        return this.publicKey.getModulusLength().getValue() * 8;
    }

    public void setSharedSecret(BigInteger sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public boolean areParametersSet() {
        return publicKey != null && hashLength != 0;
    }
}
