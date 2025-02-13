/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageSerializer
        extends SshMessageSerializer<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeInitMessageSerializer(HybridKeyExchangeInitMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        appendInt(
                message.getPublicValuesLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Public values length: {}", message.getPublicValuesLength().getValue());
        appendBytes(message.getPublicValues().getValue());
        LOGGER.debug(
                "Public values: {}",
                ArrayConverter.bytesToHexString(message.getPublicValues().getValue()));
    }
}
