/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchange extends KeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();

    protected final KeyExchangeAlgorithm algorithm;
    protected final KeyAgreement keyAgreement;
    protected final KeyEncapsulation keyEncapsulation;
    private final int pkAgreementLength;
    private final int pkEncapsulationLength;
    private final int ciphertextLength;
    private final HybridKeyExchangeCombiner combiner;

    @SuppressWarnings("SameParameterValue")
    protected HybridKeyExchange(
            KeyExchangeAlgorithm algorithm,
            KeyAgreement keyAgreement,
            KeyEncapsulation keyEncapsulation,
            HybridKeyExchangeCombiner combiner,
            int pkAgreementLength,
            int pkEncapsulationLength,
            int ciphertextLength) {
        super();
        this.algorithm = algorithm;
        this.keyAgreement = keyAgreement;
        this.keyEncapsulation = keyEncapsulation;
        this.combiner = combiner;
        this.pkAgreementLength = pkAgreementLength;
        this.pkEncapsulationLength = pkEncapsulationLength;
        this.ciphertextLength = ciphertextLength;
    }

    public static HybridKeyExchange newInstance(
            SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.HYBRID) {
            LOGGER.warn("Could not create HybridKeyExchange from {}", algorithm);
            algorithm = context.getConfig().getDefaultHybridKeyExchangeAlgorithm();
            LOGGER.warn(
                    "Trying to instantiate new Hybrid key exchange falling back to {}", algorithm);
        }

        try {
            if (!algorithm.isImplemented()) {
                LOGGER.warn(
                        "Algorithm {}is not yet implemented. Falling back to {}",
                        algorithm,
                        KeyExchangeAlgorithm.SNTRUP761_X25519);
                algorithm = KeyExchangeAlgorithm.SNTRUP761_X25519;
            }
            Class<?> kexImplementation = Class.forName(algorithm.getClassName());
            return (HybridKeyExchange) kexImplementation.getConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            LOGGER.fatal(
                    "Unable to create new instance of HybridKeyExchange, module SSH-Core-OQS is not available. Make sure to enable OpenQuantumSafe support by enabling the corresponding profile during build!");
            System.exit(1);
            return null;
        } catch (InvocationTargetException e) {
            LOGGER.fatal("Unable to invoke the default constructor of class {}", algorithm.name());
            System.exit(1);
            return null;
        } catch (InstantiationException e) {
            LOGGER.fatal(
                    "Unable to create new object by constructor invocation of class {}",
                    algorithm.name());
            System.exit(1);
            return null;
        } catch (IllegalAccessException e) {
            LOGGER.fatal("Unable to access the default constructor of class {}", algorithm.name());
            System.exit(1);
            return null;
        } catch (NoSuchMethodException e) {
            LOGGER.fatal(
                    "Unable to create new instance of HybridKeyExchange, default constructor of class {} not found. Did the method signature change?",
                    algorithm.name());
            System.exit(1);
            return null;
        }
    }

    public KeyExchangeAlgorithm getAlgorithm() {
        return algorithm;
    }

    public KeyAgreement getKeyAgreement() {
        return keyAgreement;
    }

    public KeyEncapsulation getKeyEncapsulation() {
        return keyEncapsulation;
    }

    protected static byte[] mergeKeyExchangeShares(
            byte[] firstKeyExchangeShare, byte[] secondKeyExchangeShare) {
        return ArrayConverter.concatenate(firstKeyExchangeShare, secondKeyExchangeShare);
    }

    protected static byte[] encode(byte[] sharedSecret, String hashAlgorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashAlgorithm);
            return md.digest(sharedSecret);

        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Could not get MessageDigest", e);
        }
        return new byte[0];
    }

    public void combineSharedSecrets() {
        try {
            keyAgreement.computeSharedSecret();
            if (keyEncapsulation.getSharedSecret() == null) {
                keyEncapsulation.decryptSharedSecret();
            }

            byte[] tmpSharedSecret;
            switch (combiner) {
                case CLASSICAL_CONCATENATE_POSTQUANTUM:
                    tmpSharedSecret =
                            mergeKeyExchangeShares(
                                    keyAgreement.getSharedSecret(),
                                    keyEncapsulation.getSharedSecret());
                    break;
                case POSTQUANTUM_CONCATENATE_CLASSICAL:
                    tmpSharedSecret =
                            mergeKeyExchangeShares(
                                    keyEncapsulation.getSharedSecret(),
                                    keyAgreement.getSharedSecret());
                    break;
                default:
                    throw new IllegalArgumentException(combiner.name() + " not supported.");
            }

            sharedSecret = encode(tmpSharedSecret, algorithm.getDigest());
            LOGGER.debug(
                    "Concatenated Shared Secret = {}",
                    ArrayConverter.bytesToRawHexString(tmpSharedSecret));
            LOGGER.debug(
                    "Encoded Shared Secret = {}",
                    ArrayConverter.bytesToRawHexString(
                            encode(tmpSharedSecret, algorithm.getDigest())));
        } catch (Exception e) {
            LOGGER.warn("Could not create the shared secret", e);
        }
    }

    public int getPkAgreementLength() {
        return pkAgreementLength;
    }

    public int getPkEncapsulationLength() {
        return pkEncapsulationLength;
    }

    public int getCiphertextLength() {
        return ciphertextLength;
    }

    public HybridKeyExchangeCombiner getCombiner() {
        return combiner;
    }
}
