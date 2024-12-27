/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.*;

public class Sntrup4591761x25519KeyExchange extends HybridKeyExchange {

    public Sntrup4591761x25519KeyExchange() {
        super(
                KeyExchangeAlgorithm.SNTRUP4591761_X25519,
                new XCurveEcdhKeyExchange(NamedEcGroup.CURVE25519, false),
                new SntrupKeyExchange(PQKemNames.SNTRUP4591761),
                HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                CryptoConstants.X25519_POINT_SIZE,
                CryptoConstants.SNTRUP4591761_PUBLIC_KEY_SIZE,
                CryptoConstants.SNTRUP4591761_CIPHERTEXT_SIZE);
    }
}
