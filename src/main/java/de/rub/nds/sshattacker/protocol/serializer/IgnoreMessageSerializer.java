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

import de.rub.nds.sshattacker.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.util.Converter;

public class IgnoreMessageSerializer extends MessageSerializer<IgnoreMessage> {

    public IgnoreMessageSerializer(IgnoreMessage msg) {
        super(msg);
    }

    private void serializeData() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getData().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeData();
        return getAlreadySerialized();
    }

}
