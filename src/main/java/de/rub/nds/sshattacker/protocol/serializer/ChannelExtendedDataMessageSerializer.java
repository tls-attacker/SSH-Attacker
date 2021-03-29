/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.util.Converter;

public class ChannelExtendedDataMessageSerializer extends MessageSerializer<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageSerializer(ChannelExtendedDataMessage msg) {
        super(msg);
    }

    private void serializeRecipientChannel() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeDataTypeCode() {
        appendInt(msg.getDataTypeCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeData() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getData().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeDataTypeCode();
        serializeData();
        return getAlreadySerialized();
    }

}
