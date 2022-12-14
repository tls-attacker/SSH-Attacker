/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core.SntrupParameterSet;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CustomSntrup4591761x25519KeyExchange extends HybridKeyExchange {
    private static final Logger LOGGER = LogManager.getLogger();

    public CustomSntrup4591761x25519KeyExchange() {
        super(
                new XCurveEcdhKeyExchange(NamedEcGroup.CURVE25519),
                new CustomSntrup(SntrupParameterSet.KEM_SNTRUP_761, true),
                HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL,
                CryptoConstants.X25519_POINT_SIZE,
                CryptoConstants.SNTRUP4591761_PUBLIC_KEY_SIZE,
                CryptoConstants.SNTRUP4591761_CIPHERTEXT_SIZE);
    }

    @Override
    public void combineSharedSecrets() {
        try {
            agreement.computeSharedSecret();
            if (encapsulation.getSharedSecret() == null) {
                encapsulation.decryptSharedSecret();
            }

            byte[] tmpSharedSecret =
                    mergeKeyExchangeShares(
                            ArrayConverter.bigIntegerToByteArray(encapsulation.getSharedSecret()),
                            ArrayConverter.bigIntegerToByteArray(agreement.getSharedSecret()));
            this.sharedSecret = new BigInteger(encode(tmpSharedSecret, "SHA-512"));
            LOGGER.debug(
                    "Concatenated Shared Secret = "
                            + ArrayConverter.bytesToRawHexString(tmpSharedSecret));
            LOGGER.debug(
                    "Encoded Shared Secret = "
                            + ArrayConverter.bytesToRawHexString(
                                    encode(tmpSharedSecret, "SHA-512")));
        } catch (Exception e) {
            LOGGER.warn("Could not create the shared Secret: " + e);
        }
    }
}
