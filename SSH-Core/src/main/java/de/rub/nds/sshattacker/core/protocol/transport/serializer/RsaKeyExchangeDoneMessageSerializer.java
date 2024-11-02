/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeDoneMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangeDoneMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangeDoneMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RsaKeyExchangeDoneMessageSerializer(RsaKeyExchangeDoneMessage message) {
        super(message);
    }

    private void serializeSignature() {
        Integer signatureLength = message.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        appendInt(signatureLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature: {}", message.getSignature());
        appendBytes(message.getSignature().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeSignature();
    }
}
