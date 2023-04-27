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
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.state.SshContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractEcdhKeyExchange extends DhBasedKeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final NamedEcGroup group;

    protected AbstractEcdhKeyExchange(NamedEcGroup group) {
        this.group = group;
    }

    public static AbstractEcdhKeyExchange newInstance(
            SshContext context, KeyExchangeAlgorithm algorithm) {
        if (algorithm == null || algorithm.getFlowType() != KeyExchangeFlowType.ECDH) {
            algorithm = context.getConfig().getDefaultEcdhKeyExchangeAlgorithm();
            LOGGER.warn(
                    "Trying to instantiate a new ECDH or X curve ECDH key exchange without a matching key exchange algorithm negotiated, falling back to "
                            + algorithm);
        }
        NamedEcGroup group;
        switch (algorithm) {
            case CURVE25519_SHA256:
            case CURVE25519_SHA256_LIBSSH_ORG:
                return new XCurveEcdhKeyExchange(NamedEcGroup.CURVE25519, true);
            case CURVE448_SHA512:
                return new XCurveEcdhKeyExchange(NamedEcGroup.CURVE448, true);
            case ECDH_SHA2_NISTP256:
                group = NamedEcGroup.SECP256R1;
                break;
            case ECDH_SHA2_NISTP384:
                group = NamedEcGroup.SECP384R1;
                break;
            case ECDH_SHA2_NISTP521:
                group = NamedEcGroup.SECP521R1;
                break;
            default:
                final String[] kexParts = algorithm.name().split("_", 3);
                if (kexParts.length != 3) {
                    LOGGER.error(
                            "Failed to find EC group name in algorithm name '{}'",
                            algorithm.name());
                    throw new IllegalArgumentException(
                            String.format(
                                    "EcdhKeyExchange does not implement support for algorithm '%s'",
                                    algorithm.name()));
                }
                group = NamedEcGroup.valueOf(kexParts[2]);
                break;
        }
        return new EcdhKeyExchange(group);
    }
}
