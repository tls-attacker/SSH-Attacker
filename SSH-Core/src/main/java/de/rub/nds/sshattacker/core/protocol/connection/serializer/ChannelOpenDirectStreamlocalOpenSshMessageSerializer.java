/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenDirectStreamlocalOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenDirectStreamlocalOpenSshMessageSerializer
        extends ChannelOpenMessageSerializer<ChannelOpenDirectStreamlocalOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenDirectStreamlocalOpenSshMessageSerializer(
            ChannelOpenDirectStreamlocalOpenSshMessage message) {
        super(message);
    }

    private void serializeSocketPath() {
        LOGGER.debug("Socket path length: {}", message.getSocketPathLength().getValue());
        appendInt(message.getSocketPathLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Socket path: {}", message.getSocketPath().getValue());
        appendString(message.getSocketPath().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeReservedString() {
        LOGGER.debug("Reserved string length: {}", message.getReservedStringLength().getValue());
        appendInt(
                message.getReservedStringLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Reserved string: {}",
                ArrayConverter.bytesToRawHexString(message.getReservedString().getValue()));
        appendBytes(message.getReservedString().getValue());
    }

    private void serializeReservedUint32() {
        LOGGER.debug("Reserved uint32: {}", message.getReservedUint32().getValue());
        appendInt(message.getReservedUint32().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSocketPath();
        serializeReservedString();
        serializeReservedUint32();
    }
}
