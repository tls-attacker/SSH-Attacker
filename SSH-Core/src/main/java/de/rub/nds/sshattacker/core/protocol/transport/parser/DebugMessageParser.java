/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;

public class DebugMessageParser extends MessageParser<DebugMessage> {

    public DebugMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public DebugMessage createMessage() {
        return new DebugMessage();
    }

    private void parseAlwaysDisplay(DebugMessage msg) {
        msg.setAlwaysDisplay(parseByteField(1) != 0);
    }

    private void parseMessage(DebugMessage msg) {
        msg.setMessage(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    private void parseLanguageTag(DebugMessage msg) {
        msg.setLanguageTag(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    @Override
    protected void parseMessageSpecificPayload(DebugMessage msg) {
        parseAlwaysDisplay(msg);
        parseMessage(msg);
        parseLanguageTag(msg);
    }
}
