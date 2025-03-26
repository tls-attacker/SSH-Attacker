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

    public ChannelOpenX11MessageHandler(SshContext context) {
        super(context);
    }

    public ChannelOpenX11MessageHandler(SshContext context, ChannelOpenX11Message message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public ChannelOpenX11MessageParser getParser(byte[] array) {
        return new ChannelOpenX11MessageParser(array);
    }

    @Override
    public ChannelOpenX11MessageParser getParser(byte[] array, int startPosition) {
        return new ChannelOpenX11MessageParser(array, startPosition);
    }

    @Override
    public ChannelOpenX11MessagePreparator getPreparator() {
        return new ChannelOpenX11MessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelOpenX11MessageSerializer getSerializer() {
        return new ChannelOpenX11MessageSerializer(message);
    }
}
