/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;

public class ChannelOpenSessionMessageParser
        extends ChannelOpenMessageParser<ChannelOpenSessionMessage> {
    public ChannelOpenSessionMessageParser(byte[] array) {
        super(array);
    }

    public ChannelOpenSessionMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelOpenSessionMessage createMessage() {
        return new ChannelOpenSessionMessage();
    }
}
