/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PQKemNames;

public class Curve25519Frodokem1344KeyExchange extends HybridKeyExchange {

    public Curve25519Frodokem1344KeyExchange() {

        super(
                KeyExchangeAlgorithm.CURVE25519_FRODOKEM1344,
                new XCurveEcdhKeyExchange(NamedEcGroup.CURVE25519, false),
                new OpenQuantumSafeKem(PQKemNames.FRODOKEM1344),
                HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                CryptoConstants.X25519_POINT_SIZE,
                CryptoConstants.FRODOKEM1344_PUBLIC_KEY_SIZE,
                CryptoConstants.FRODOKEM1344_CIPHERTEXT_SIZE);
    }
}
