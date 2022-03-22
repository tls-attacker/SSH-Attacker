/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractEcdhKeyExchange extends DhBasedKeyExchange {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final NamedGroup group;

    protected AbstractEcdhKeyExchange(NamedGroup group) {
        this.group = group;
    }

    public static AbstractEcdhKeyExchange newInstance(
            SshContext context, KeyExchangeAlgorithm negotiatedKexAlgorithm) {
        if (negotiatedKexAlgorithm == null) {
            return new EcdhKeyExchange(context.getConfig().getDefaultEcdhKeyExchangeGroup());
        }
        NamedGroup group;
        switch (negotiatedKexAlgorithm) {
            case CURVE25519_SHA256:
            case CURVE25519_SHA256_LIBSSH_ORG:
                return new XCurveEcdhKeyExchange(NamedGroup.ECDH_X25519);
            case CURVE448_SHA512:
                return new XCurveEcdhKeyExchange(NamedGroup.ECDH_X448);
            case ECDH_SHA2_NISTP256:
                group = NamedGroup.SECP256R1;
                break;
            case ECDH_SHA2_NISTP384:
                group = NamedGroup.SECP384R1;
                break;
            case ECDH_SHA2_NISTP521:
                group = NamedGroup.SECP521R1;
                break;
            default:
                String[] kexParts = negotiatedKexAlgorithm.name().split("_");
                if (!kexParts[0].equals("ECDH")) {
                    LOGGER.warn(
                            "Initializing a new ECDHKeyExchange without an ECDH key exchange algorithm negotiated. Falling back to ecdh-sha2-nistp256.");
                    group = context.getConfig().getDefaultEcdhKeyExchangeGroup();
                } else {
                    group = NamedGroup.valueOf(kexParts[3]);
                }
                break;
        }
        return new EcdhKeyExchange(group);
    }
}
