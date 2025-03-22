/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenSessionMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenSessionMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenSessionMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenSessionMessageHandler extends SshMessageHandler<ChannelOpenSessionMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelOpenSessionMessage object) {
        context.getChannelManager().handleChannelOpenMessage(object);
    }

    @Override
    public ChannelOpenSessionMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelOpenSessionMessageParser(array);
    }

    @Override
    public ChannelOpenSessionMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelOpenSessionMessageParser(array, startPosition);
    }

    public static final ChannelOpenSessionMessagePreparator PREPARATOR =
            new ChannelOpenSessionMessagePreparator();

    public static final ChannelOpenSessionMessageSerializer SERIALIZER =
            new ChannelOpenSessionMessageSerializer();
}
