/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.message.ChannelExtendedDataMessage;

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
        appendBytes(Converter.bytesToLengthPrefixedBinaryString(msg.getData().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeDataTypeCode();
        serializeData();
        return getAlreadySerialized();
    }

}
