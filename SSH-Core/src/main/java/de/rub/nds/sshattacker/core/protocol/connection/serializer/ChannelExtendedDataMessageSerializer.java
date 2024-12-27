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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelExtendedDataMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelExtendedDataMessageSerializer
        extends ChannelMessageSerializer<ChannelExtendedDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeDataTypeCode(
            ChannelExtendedDataMessage object, SerializerStream output) {
        LOGGER.debug("Data type code: {}", object.getDataTypeCode().getValue());
        LOGGER.debug(
                "Data type: {}",
                ExtendedChannelDataType.fromDataTypeCode(object.getDataTypeCode().getValue()));
        output.appendInt(object.getDataTypeCode().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private static void serializeData(ChannelExtendedDataMessage object, SerializerStream output) {
        Integer dataLength = object.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        output.appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = object.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        output.appendBytes(data);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelExtendedDataMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeDataTypeCode(object, output);
        serializeData(object, output);
    }
}
