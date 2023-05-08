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
import de.rub.nds.sshattacker.core.state.SshContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public abstract class HybridKeyExchange extends KeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();

    protected final KeyExchangeAlgorithm algorithm;
    protected final KeyAgreement agreement;
    protected final KeyEncapsulation encapsulation;
    private final int pkAgreementLength;
    private final int pkEncapsulationLength;
    private final int ciphertextLength;
    private final HybridKeyExchangeCombiner combiner;

    @SuppressWarnings("SameParameterValue")
    protected HybridKeyExchange(
            KeyExchangeAlgorithm algorithm,
            KeyAgreement agreement,
            KeyEncapsulation encapsulation,
            HybridKeyExchangeCombiner combiner,
            int pkAgreementLength,
            int pkEncapsulationLength,
            int ciphertextLength) {
        super();
        this.algorithm = algorithm;
        this.agreement = agreement;
        this.encapsulation = encapsulation;
        this.combiner = combiner;
        this.pkAgreementLength = pkAgreementLength;
        this.pkEncapsulationLength = pkEncapsulationLength;
        this.ciphertextLength = ciphertextLength;
    }

    public static HybridKeyExchange newInstance(
            SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.HYBRID) {
            LOGGER.warn("Could not create HybridKeyExchange from " + algorithm);
            algorithm = context.getConfig().getDefaultHybridKeyExchangeAlgorithm();
            LOGGER.warn(
                    "Trying to instantiate new Hybrid key exchange falling back to " + algorithm);
        }

        try {
            if (!algorithm.isImplemented()) {
                LOGGER.warn(
                        "Algorithm "
                                + algorithm
                                + "is not yet implemented. Falling back to "
                                + KeyExchangeAlgorithm.SNTRUP761_X25519);
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
            LOGGER.fatal("Unable to invoke the default constructor of class " + algorithm.name());
            System.exit(1);
            return null;
        } catch (InstantiationException e) {
            LOGGER.fatal(
                    "Unable to create new object by constructor invocation of class "
                            + algorithm.name());
            System.exit(1);
            return null;
        } catch (IllegalAccessException e) {
            LOGGER.fatal("Unable to access the default constructor of class " + algorithm.name());
            System.exit(1);
            return null;
        } catch (NoSuchMethodException e) {
            LOGGER.fatal(
                    "Unable to create new instance of HybridKeyExchange, default constructor of class "
                            + algorithm.name()
                            + " not found. Did the method signature change?");
            System.exit(1);
            return null;
        }
    }

    public KeyExchangeAlgorithm getAlgorithm() {
        return algorithm;
    }

    public KeyAgreement getKeyAgreement() {
        return agreement;
    }

    public KeyEncapsulation getKeyEncapsulation() {
        return encapsulation;
    }

    protected byte[] mergeKeyExchangeShares(
            byte[] firstKeyExchangeShare, byte[] secondKeyExchangeShare) {
        return ArrayConverter.concatenate(firstKeyExchangeShare, secondKeyExchangeShare);
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

    public void combineSharedSecrets() {
        try {
            agreement.computeSharedSecret();
            if (encapsulation.getSharedSecret() == null) {
                encapsulation.decryptSharedSecret();
            }

            byte[] tmpSharedSecret;
            switch (combiner) {
                case CLASSICAL_CONCATENATE_POSTQUANTUM:
                    tmpSharedSecret =
                            mergeKeyExchangeShares(
                                    agreement.getSharedSecret(), encapsulation.getSharedSecret());
                    break;
                case POSTQUANTUM_CONCATENATE_CLASSICAL:
                    tmpSharedSecret =
                            mergeKeyExchangeShares(
                                    encapsulation.getSharedSecret(), agreement.getSharedSecret());
                    break;
                default:
                    throw new IllegalArgumentException(combiner.name() + " not supported.");
            }

            this.sharedSecret = encode(tmpSharedSecret, algorithm.getDigest());
            LOGGER.debug(
                    "Concatenated Shared Secret = "
                            + ArrayConverter.bytesToRawHexString(tmpSharedSecret));
            LOGGER.debug(
                    "Encoded Shared Secret = "
                            + ArrayConverter.bytesToRawHexString(
                                    encode(tmpSharedSecret, algorithm.getDigest())));
        } catch (Exception e) {
            LOGGER.warn("Could not create the shared Secret: " + e);
        }
    }

    public int getPkAgreementLength() {
        return this.pkAgreementLength;
    }

    public int getPkEncapsulationLength() {
        return this.pkEncapsulationLength;
    }

    public int getCiphertextLength() {
        return this.ciphertextLength;
    }

    public HybridKeyExchangeCombiner getCombiner() {
        return this.combiner;
    }
}
