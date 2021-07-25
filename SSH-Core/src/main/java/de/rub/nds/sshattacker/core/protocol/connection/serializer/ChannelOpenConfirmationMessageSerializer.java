/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;

public class ChannelOpenConfirmationMessageSerializer extends MessageSerializer<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessageSerializer(ChannelOpenConfirmationMessage msg) {
        super(msg);
    }

    private void serializeRecipientChannel() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeSenderChannel() {
        appendInt(msg.getSenderChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeWindowSize() {
        appendInt(msg.getWindowSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializePacketSize() {
        appendInt(msg.getPacketSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
        return getAlreadySerialized();
    }

}
