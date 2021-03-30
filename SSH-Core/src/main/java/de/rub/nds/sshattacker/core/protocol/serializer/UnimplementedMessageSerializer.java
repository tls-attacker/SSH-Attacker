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
import de.rub.nds.sshattacker.core.protocol.message.UnimplementedMessage;

public class UnimplementedMessageSerializer extends MessageSerializer<UnimplementedMessage> {

    public UnimplementedMessageSerializer(UnimplementedMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendInt(msg.getSequenceNumber().getValue(), DataFormatConstants.INT32_SIZE);
        return getAlreadySerialized();
    }

}
