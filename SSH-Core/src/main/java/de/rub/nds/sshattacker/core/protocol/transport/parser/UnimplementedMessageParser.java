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
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;

public class UnimplementedMessageParser extends MessageParser<UnimplementedMessage> {

    public UnimplementedMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public UnimplementedMessage createMessage() {
        return new UnimplementedMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(UnimplementedMessage msg) {
        msg.setSequenceNumber(parseIntField(DataFormatConstants.INT32_SIZE));
    }

}
