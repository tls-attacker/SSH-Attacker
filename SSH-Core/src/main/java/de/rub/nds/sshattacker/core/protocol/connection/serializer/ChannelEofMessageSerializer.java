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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelEofMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;

public class ChannelEofMessageSerializer extends MessageSerializer<ChannelEofMessage> {

    public ChannelEofMessageSerializer(ChannelEofMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
        return getAlreadySerialized();
    }

}
