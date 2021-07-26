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

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelCloseMessage;

public class ChannelCloseMessageParser extends ChannelMessageParser<ChannelCloseMessage> {

    public ChannelCloseMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public ChannelCloseMessage createMessage() {
        return new ChannelCloseMessage();
    }
}
