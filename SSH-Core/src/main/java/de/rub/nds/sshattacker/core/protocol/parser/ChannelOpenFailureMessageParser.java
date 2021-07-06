/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.message.ChannelOpenFailureMessage;

public class ChannelOpenFailureMessageParser extends MessageParser<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelOpenFailureMessage createMessage() {
        return new ChannelOpenFailureMessage();
    }

    private void parseRecipientChannel(ChannelOpenFailureMessage msg) {
        msg.setRecipientChannel(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseReasonCode(ChannelOpenFailureMessage msg) {
        msg.setReasonCode(parseIntField(DataFormatConstants.INT32_SIZE));
    }

    private void parseReason(ChannelOpenFailureMessage msg) {
        msg.setReason(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    private void parseLanguageTag(ChannelOpenFailureMessage msg) {
        msg.setLanguageTag(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelOpenFailureMessage msg) {
        parseRecipientChannel(msg);
        parseReasonCode(msg);
        parseReason(msg);
        parseLanguageTag(msg);
    }
}
