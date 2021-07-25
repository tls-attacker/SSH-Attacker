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

import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;

public class GlobalRequestMessageSerializer extends MessageSerializer<GlobalRequestMessage> {

    public GlobalRequestMessageSerializer(GlobalRequestMessage msg) {
        super(msg);
    }

    private void serializeRequestName() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getRequestName().getValue()));
    }

    private void serializeWantReplay() {
        appendByte(msg.getWantReply().getValue());
    }

    private void serializePayload() {
        appendBytes(msg.getPayload().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRequestName();
        serializeWantReplay();
        serializePayload();
        return getAlreadySerialized();
    }

}
