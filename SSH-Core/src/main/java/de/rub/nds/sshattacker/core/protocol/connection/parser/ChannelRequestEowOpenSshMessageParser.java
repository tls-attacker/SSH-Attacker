/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEowOpenSshMessage;

public class ChannelRequestEowOpenSshMessageParser
        extends ChannelRequestMessageParser<ChannelRequestEowOpenSshMessage> {

    public ChannelRequestEowOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestEowOpenSshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected ChannelRequestEowOpenSshMessage createMessage() {
        return new ChannelRequestEowOpenSshMessage();
    }
}
