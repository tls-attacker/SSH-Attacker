/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
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

    public ChannelExtendedDataMessageSerializer(ChannelExtendedDataMessage msg) {
        super(msg);
    }

    private void serializeDataTypeCode() {
        LOGGER.debug("Data type code: " + msg.getDataTypeCode().getValue());
        LOGGER.debug(
                "Data type: "
                        + ExtendedChannelDataType.fromDataTypeCode(
                                msg.getDataTypeCode().getValue()));
        appendInt(msg.getDataTypeCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeData() {
        LOGGER.debug("Data length: " + msg.getDataLength().getValue());
        appendInt(msg.getDataLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Data: " + ArrayConverter.bytesToRawHexString(msg.getData().getValue()));
        appendBytes(msg.getData().getValue());
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        super.serializeMessageSpecificPayload();
        serializeDataTypeCode();
        serializeData();
    }
}
