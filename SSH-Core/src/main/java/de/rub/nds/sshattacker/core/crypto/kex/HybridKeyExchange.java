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
import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class HybridKeyExchange extends KeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();
    protected KeyAgreement agreement;
    protected KeyEncapsulation encapsulation;
    private int pkAgreementLength;
    private int pkEncapsulationLength;
    private int ciphertextLength;
    private HybridKeyExchangeCombiner combiner;

    protected HybridKeyExchange(
            KeyAgreement agreement,
            KeyEncapsulation encapsulation,
            HybridKeyExchangeCombiner combiner,
            int pkAgreementLength,
            int pkEncapsulationLength,
            int ciphertextLength) {
        super();
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
            switch (algorithm) {
                default:
                    LOGGER.warn(
                            "Algorithm "
                                    + algorithm
                                    + "is not supported. Falling back to "
                                    + KeyExchangeAlgorithm.SNTRUP761_X25519);
                    // Fallthrough to case SNTRUP761_X25519 intended
                case SNTRUP761_X25519:
                    // Check if SSH-Core-PQC module has been compiled and is available
                    Class<?> sntrup761x25519 =
                            Class.forName(
                                    "de.rub.nds.sshattacker.core.crypto.kex.Sntrup761X25519KeyExchange");
                    return (HybridKeyExchange) sntrup761x25519.getConstructor().newInstance();

                case CURVE25519_FRODOKEM1344:
                    Class<?> curve25519xfrodokem1344 =
                            Class.forName(
                                    "de.rub.nds.sshattacker.core.crypto.kex.Curve25519Frodokem1344KeyExchange");
                    return (HybridKeyExchange)
                            curve25519xfrodokem1344.getConstructor().newInstance();
                case SNTRUP4591761_x25519:
                    Class<?> sntrup4591761x25519 =
                            Class.forName(
                                    "de.rub.nds.sshattacker.core.crypto.kex.CustomSntrup4591761x25519KeyExchange");
                    return (HybridKeyExchange) sntrup4591761x25519.getConstructor().newInstance();
            }

        } catch (ClassNotFoundException e) {
            LOGGER.fatal(
                    "Unable to create new instance of HybridKeyExchange, module SSH-Core-PQC is not available. Make sure to enable PQC by enabling the corresponding profile during build!");
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

    public abstract void combineSharedSecrets();

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
