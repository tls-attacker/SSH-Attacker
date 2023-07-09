/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestShellMessage;
import java.io.InputStream;

public class ChannelRequestShellMessageParser
        extends ChannelRequestMessageParser<ChannelRequestShellMessage> {

    /*    public ChannelRequestShellMessageParser(byte[] array) {
        super(array);
    }
    public ChannelRequestShellMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/
    public ChannelRequestShellMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestShellMessage message) {
        parseProtocolMessageContents(message);
    }

    /*    @Override
    public ChannelRequestShellMessage createMessage() {
        return new ChannelRequestShellMessage();
    }*/
}
