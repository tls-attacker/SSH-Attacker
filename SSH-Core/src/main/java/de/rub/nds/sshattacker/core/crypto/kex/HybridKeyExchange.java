/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchange extends KeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HybridKeyExchangeCombiner combiner;
    private final HashFunction hashFunction;
    private final AbstractEcdhKeyExchange<?, ?> classical;
    private final KemKeyExchange postQuantum;

    protected HybridKeyExchange(
            HybridKeyExchangeCombiner combiner,
            HashFunction hashFunction,
            AbstractEcdhKeyExchange<?, ?> classical,
            KemKeyExchange postQuantum) {
        super();
        this.combiner = combiner;
        this.hashFunction = hashFunction;
        this.classical = classical;
        this.postQuantum = postQuantum;
    }

    public static HybridKeyExchange newInstance(
            SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.HYBRID) {
            LOGGER.warn(
                    "Algorithm {} is no hybrid key exchange algorithm, falling back to {}",
                    algorithm,
                    context.getConfig().getDefaultHybridKeyExchangeAlgorithm());
            algorithm = context.getConfig().getDefaultHybridKeyExchangeAlgorithm();
        }
        return switch (algorithm) {
            case SNTRUP761_X25519 ->
                    new HybridKeyExchange(
                            HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                            HashFunction.SHA512,
                            new XCurveEcdhKeyExchange(NamedEcGroup.CURVE25519, false),
                            new KemKeyExchange(KemAlgorithm.SNTRUP761));
            default -> null;
        };
    }

    @Override
    public void generateKeyPair() throws CryptoException {
        classical.generateKeyPair();
        postQuantum.generateKeyPair();
    }

    public HybridKeyExchangeCombiner getCombiner() {
        return combiner;
    }

    public HashFunction getHashFunction() {
        return hashFunction;
    }

    public AbstractEcdhKeyExchange<?, ?> getClassical() {
        return classical;
    }

    public int getClassicalPublicKeySize() {
        return classical.getGroup().getPointSize();
    }

    public KemKeyExchange getPostQuantum() {
        return postQuantum;
    }

    public int getPostQuantumPublicKeySize() {
        return postQuantum.getKemAlgorithm().getPublicKeySize();
    }

    public int getPostQuantumEncapsulationSize() {
        return postQuantum.getKemAlgorithm().getEncapsulationSize();
    }

    public void computeSharedSecret() throws CryptoException {
        if (!classical.isComplete()) {
            classical.computeSharedSecret();
        }
        if (!postQuantum.isComplete()) {
            postQuantum.decapsulate();
        }
        byte[] sharedSecretClassical = classical.getSharedSecret();
        byte[] sharedSecretPostQuantum = postQuantum.getSharedSecret();
        try {
            MessageDigest digest = MessageDigest.getInstance(hashFunction.getJavaName());
            if (combiner == HybridKeyExchangeCombiner.CLASSICAL_CONCATENATE_POSTQUANTUM) {
                digest.update(sharedSecretClassical);
                digest.update(sharedSecretPostQuantum);
            } else {
                digest.update(sharedSecretPostQuantum);
                digest.update(sharedSecretClassical);
            }
            sharedSecret = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(
                    "Unable to compute combined shared secret - hash function not available", e);
        }
    }
}
