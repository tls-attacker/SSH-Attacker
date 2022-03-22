/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchange extends KeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private RSAPublicKey publicKey;

    // HLEN in RFC 4432 (in bits)
    private int hashLength;

    protected RsaKeyExchange() {}

    protected RsaKeyExchange(int hashLength) {
        this.hashLength = hashLength;
    }

    public static RsaKeyExchange newInstance(
            SshContext context, KeyExchangeAlgorithm negotiatedKexAlgorithm) {
        if (negotiatedKexAlgorithm == null) {
            return new RsaKeyExchange();
        }
        int hashLength;
        switch (negotiatedKexAlgorithm) {
            case RSA1024_SHA1:
                hashLength = 160;
                break;
            case RSA2048_SHA256:
                hashLength = 256;
                break;
            default:
                LOGGER.warn(
                        "Initializing a new RsaKeyExchange without an RSA key exchange algorithm negotiated, falling back to default algorithm");
                hashLength =
                        context.getConfig().getDefaultRsaKeyExchangeAlgorithm()
                                        == KeyExchangeAlgorithm.RSA1024_SHA1
                                ? 160
                                : 256;
                break;
        }
        return new RsaKeyExchange(hashLength);
    }

    @Override
    public void computeSharedSecret() {
        // Calculation of maximum number of bits taken from RFC 4432
        int maximumBits = (getModulusLengthInBits() - 2 * hashLength - 49);
        sharedSecret = new BigInteger(maximumBits, random);
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public RSAPublicKey getPublicKey() {
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

    private int getModulusLengthInBits() {
        return publicKey.getModulus().bitLength();
    }

    public void setSharedSecret(BigInteger sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public boolean areParametersSet() {
        return publicKey != null && hashLength != 0;
    }
}
