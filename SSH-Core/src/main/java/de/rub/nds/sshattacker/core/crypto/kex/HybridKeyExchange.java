/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class HybridKeyExchange
        extends KeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();
    protected KeyAgreement agreement;
    protected KeyEncapsulation encapsulation;

    protected HybridKeyExchange(KeyAgreement agreement, KeyEncapsulation encapsulation) {
        super();
        this.agreement = agreement;
        this.encapsulation = encapsulation;
    }

    public static HybridKeyExchange newInstance(
            SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.HYBRID) {
            LOGGER.warn("Could not create HybridKeyExchange from " + algorithm);
            algorithm = context.getConfig().getDefaultHybridKeyExchangeAlgorithm();
            LOGGER.warn(
                    "Trying to instantiate new Hybrid key exchange falling back to " + algorithm);
        }

        switch (algorithm) {
            case SNTRUP761_X25519:
                return new Sntrup761X25519KeyExchange();
            default:
                LOGGER.warn(
                        "Algorithm "
                                + algorithm
                                + "is not supported. Falling back to "
                                + KeyExchangeAlgorithm.SNTRUP761_X25519);
                return new Sntrup761X25519KeyExchange();
        }
    }

    public KeyAgreement getKeyAgreement() {
        return agreement;
    }

    public KeyEncapsulation getKeyEncapsulation() {
        return encapsulation;
    }

    protected byte[] mergeKeyExchanges(byte[] keyExchange1, byte[] keyExchange2) {
        byte[] mergedKeys = new byte[keyExchange1.length + keyExchange2.length];
        ByteBuffer buff = ByteBuffer.wrap(mergedKeys);
        buff.put(keyExchange1);
        buff.put(keyExchange2);
        return buff.array();
    }

    protected byte[] encode(byte[] sharedSecret, String hashAlgorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            return md.digest(sharedSecret);

        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Could not get MessageDigest: " + e);
        }
        return new byte[0];
    }
    
    public abstract void combineSharedSecrets();
}
