/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.ExtendedChannelDataType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelExtendedDataMessageSerializer
        extends ChannelMessageSerializer<ChannelExtendedDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelExtendedDataMessageSerializer(ChannelExtendedDataMessage message) {
        super(message);
    }

    private void serializeDataTypeCode() {
        LOGGER.debug("Data type code: {}", message.getDataTypeCode().getValue());
        LOGGER.debug(
                "Data type: {}",
                ExtendedChannelDataType.fromDataTypeCode(message.getDataTypeCode().getValue()));
        appendInt(message.getDataTypeCode().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeData() {
        Integer dataLength = message.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = message.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        appendBytes(data);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeDataTypeCode();
        serializeData();
    }
}
