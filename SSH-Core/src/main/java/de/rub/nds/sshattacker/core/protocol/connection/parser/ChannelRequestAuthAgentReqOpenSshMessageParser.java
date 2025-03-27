/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentReqOpenSshMessage;

public class ChannelRequestAuthAgentReqOpenSshMessageParser
        extends ChannelRequestMessageParser<ChannelRequestAuthAgentReqOpenSshMessage> {

    public ChannelRequestAuthAgentReqOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestAuthAgentReqOpenSshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessage createMessage() {
        return new ChannelRequestAuthAgentReqOpenSshMessage();
    }
}
