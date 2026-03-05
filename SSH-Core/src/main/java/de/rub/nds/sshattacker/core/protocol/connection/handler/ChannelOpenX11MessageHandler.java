/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenX11Message;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenX11MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenX11MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenX11MessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenX11MessageHandler extends SshMessageHandler<ChannelOpenX11Message> {

    @Override
    public void adjustContext(SshContext context, ChannelOpenX11Message object) {
        // TODO: Handle ChannelOpenX11Message
    }

    @Override
    public ChannelOpenX11MessageParser getParser(byte[] array, SshContext context) {
        return new ChannelOpenX11MessageParser(array);
    }

    @Override
    public ChannelOpenX11MessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenX11MessageParser(array, startPosition);
    }

    public static final ChannelOpenX11MessagePreparator PREPARATOR =
            new ChannelOpenX11MessagePreparator();

    public static final ChannelOpenX11MessageSerializer SERIALIZER =
            new ChannelOpenX11MessageSerializer();
}
