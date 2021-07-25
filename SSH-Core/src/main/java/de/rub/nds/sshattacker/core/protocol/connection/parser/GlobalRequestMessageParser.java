/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;

public class GlobalRequestMessageParser extends MessageParser<GlobalRequestMessage> {

    public GlobalRequestMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public GlobalRequestMessage createMessage() {
        return new GlobalRequestMessage();
    }

    private void parseRequestName(GlobalRequestMessage msg) {
        msg.setRequestName(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    private void parseWantReply(GlobalRequestMessage msg) {
        msg.setWantReply(parseByteField(1));
    }

    private void parsePayload(GlobalRequestMessage msg) {
        msg.setPayload(parseArrayOrTillEnd(-1));
    }

    @Override
    protected void parseMessageSpecificPayload(GlobalRequestMessage msg) {
        parseRequestName(msg);
        parseWantReply(msg);
        parsePayload(msg);
    }

}
