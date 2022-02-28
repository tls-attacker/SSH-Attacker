/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.signature;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Parser class to parse a signature */
public class SignatureParser extends Parser<RawSignature> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SignatureParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public RawSignature parse() {
        RawSignature signature = new RawSignature();
        int sigtypeLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        String sigtype = parseByteString(sigtypeLength);
        LOGGER.debug("Signature Type: " + sigtype);

        // Try to convert the signature type to get the corresponding signature algorithm
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getSignatureAlgorithm(sigtype);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        LOGGER.debug(
                "Corresponding signature algorithm: "
                        + signature.getSignatureAlgorithm().getJavaName());

        signature.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + signature.getSignatureLength());
        signature.setSignatureBytes(parseByteArrayField(signature.getSignatureLength()));
        LOGGER.debug("Signature bytes: " + Arrays.toString(signature.getSignatureBytes()));
        return signature;
    }
}
