/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.sshattacker.protocol.message.ChannelSuccessMessage;

public class ChannelSuccessMessageParser extends MessageParser<ChannelSuccessMessage> {

    public ChannelSuccessMessageParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ChannelSuccessMessage createMessage() {
        return new ChannelSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificPayload(ChannelSuccessMessage msg) {
    }

}
