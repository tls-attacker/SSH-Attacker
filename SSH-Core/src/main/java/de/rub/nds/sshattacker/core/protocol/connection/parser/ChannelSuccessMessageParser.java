/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;

public class ChannelSuccessMessageParser extends ChannelMessageParser<ChannelSuccessMessage> {

    public ChannelSuccessMessageParser(byte[] array) {
        super(array);
    }

    public ChannelSuccessMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelSuccessMessage createMessage() {
        return new ChannelSuccessMessage();
    }
}
