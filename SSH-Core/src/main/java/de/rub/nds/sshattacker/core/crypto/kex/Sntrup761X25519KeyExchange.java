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

public class Sntrup761X25519KeyExchange extends HybridKeyExchange {

    public Sntrup761X25519KeyExchange() {
        super(
                KeyExchangeAlgorithm.SNTRUP761_X25519,
                new XCurveEcdhKeyExchange(NamedEcGroup.CURVE25519),
                new Sntrup(PQKemNames.SNTRUP761),
                HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                CryptoConstants.X25519_POINT_SIZE,
                CryptoConstants.SNTRUP761_PUBLIC_KEY_SIZE,
                CryptoConstants.SNTRUP761_CIPHERTEXT_SIZE);
    }
}
