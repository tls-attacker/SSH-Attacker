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

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class HybridKeyExchange extends KeyExchange {// } implements HybridKeyExchangeAgreementInterface,
                                                             // HybridKeyExchangeEncapsulationInterface{
    private static final Logger LOGGER = LogManager.getLogger();
    protected Map<String, HybridKeyExchangeAgreement> agreement;
    protected Map<String, HybridKeyExchangeEncapsulation> encapsulation;

    protected HybridKeyExchange(){
        super();
        this.agreement = new HashMap<>();
        this.encapsulation = new HashMap<>();
    }

    public static HybridKeyExchange NewInstance(SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.HYBRID) {
            LOGGER.warn("Could not create HybridKeyExchange from " + algorithm);
            algorithm = context.getConfig().getDefaultHybridKeyExchangeAlgorithm();
            LOGGER.warn("Trying to instantiate new Hybrid key exchange falling back to " + algorithm);
        }

        switch (algorithm) {
            case SNTRUP761_X25519:
                return new Sntrup761X25519KeyExchange();
            default:
                LOGGER.warn("Algorithm " + algorithm + "is not supported. Falling back to "
                        + KeyExchangeAlgorithm.SNTRUP761_X25519);
                return new Sntrup761X25519KeyExchange();
        }
    }

    public HybridKeyExchangeAgreement getKeyAgreement(String name) {
        return agreement.getOrDefault(name, null);
    }

    public HybridKeyExchangeEncapsulation getKeyEncapsulation(String name) {
        return encapsulation.getOrDefault(name, null);
    }
    
    public abstract void combineSharedSecrets();
}
