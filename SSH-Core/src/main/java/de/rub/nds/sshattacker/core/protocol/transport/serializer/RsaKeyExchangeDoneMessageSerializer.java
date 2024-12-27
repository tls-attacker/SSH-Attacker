/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeDoneMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangeDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSignature(
            RsaKeyExchangeDoneMessage object, SerializerStream output) {
        Integer signatureLength = object.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        output.appendInt(signatureLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature: {}", object.getSignature());
        output.appendBytes(object.getSignature().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            RsaKeyExchangeDoneMessage object, SerializerStream output) {
        serializeSignature(object, output);
    }
}
