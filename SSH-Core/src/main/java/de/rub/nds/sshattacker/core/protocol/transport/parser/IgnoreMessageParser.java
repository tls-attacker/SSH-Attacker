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
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;

public class IgnoreMessageParser extends MessageParser<IgnoreMessage> {

    public IgnoreMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public IgnoreMessage createMessage() {
        return new IgnoreMessage();
    }

    private void parseData(IgnoreMessage msg) {
        msg.setData(parseByteArrayField(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)));
    }

    @Override
    protected void parseMessageSpecificPayload(IgnoreMessage msg) {
        parseData(msg);
    }

}
