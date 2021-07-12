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

import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.message.DebugMessage;

public class DebugMessageSerializer extends MessageSerializer<DebugMessage> {

    public DebugMessageSerializer(DebugMessage msg) {
        super(msg);
    }

    private void serializeAlwaysDisplayed() {
        appendByte((byte) (msg.getAlwaysDisplay().getValue() ? 0x01 : 0x00));
    }

    private void serializeMessage() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getMessage().getValue()));
    }

    private void serializeLanguageTag() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getLanguageTag().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeAlwaysDisplayed();
        serializeMessage();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
