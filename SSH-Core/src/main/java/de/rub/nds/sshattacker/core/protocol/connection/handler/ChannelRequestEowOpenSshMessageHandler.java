/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEowOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestEowOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestEowOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestEowOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestEowOpenSshMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestEowOpenSshMessage> {

    @Override
    public ChannelRequestEowOpenSshMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestEowOpenSshMessageParser(array);
    }

    @Override
    public ChannelRequestEowOpenSshMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestEowOpenSshMessageParser(array, startPosition);
    }

    public static final ChannelRequestEowOpenSshMessagePreparator PREPARATOR =
            new ChannelRequestEowOpenSshMessagePreparator();

    public static final ChannelRequestEowOpenSshMessageSerializer SERIALIZER =
            new ChannelRequestEowOpenSshMessageSerializer();
}
