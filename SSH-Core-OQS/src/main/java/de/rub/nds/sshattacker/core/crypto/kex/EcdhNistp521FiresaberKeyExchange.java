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

public class EcdhNistp521FiresaberKeyExchange extends HybridKeyExchange {

    public EcdhNistp521FiresaberKeyExchange() {
        super(
                KeyExchangeAlgorithm.NISTP521_FIRESABER,
                new EcdhKeyExchange(NamedEcGroup.SECP521R1),
                new OpenQuantumSafeKem(PQKemNames.FIRESABER),
                HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                CryptoConstants.NISTP521_POINT_SIZE,
                CryptoConstants.FIRESABER_PUBLIC_KEY_SIZE,
                CryptoConstants.FIRESABER_CIPHERTEXT_SIZE);
    }
}
