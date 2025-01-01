/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenUnknownMessageHandler extends SshMessageHandler<ChannelOpenUnknownMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelOpenUnknownMessage object) {}

    @Override
    public ChannelOpenUnknownMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelOpenUnknownMessageParser(array);
    }

    @Override
    public ChannelOpenUnknownMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenUnknownMessageParser(array, startPosition);
    }

    public static final ChannelOpenUnknownMessagePreparator PREPARATOR =
            new ChannelOpenUnknownMessagePreparator();

    public static final ChannelOpenUnknownMessageSerializer SERIALIZER =
            new ChannelOpenUnknownMessageSerializer();
}
