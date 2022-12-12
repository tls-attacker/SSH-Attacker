/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestX11MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestX11MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestX11MessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestX11MessageHandler extends SshMessageHandler<ChannelRequestX11Message> {
    public ChannelRequestX11MessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestX11MessageHandler(SshContext context, ChannelRequestX11Message message) {
        super(context, message);
    }

    @Override
    public ChannelRequestX11MessageParser getParser(byte[] array) {
        return new ChannelRequestX11MessageParser(array);
    }

    @Override
    public ChannelRequestX11MessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestX11MessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestX11MessagePreparator getPreparator() {
        return new ChannelRequestX11MessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestX11MessageSerializer getSerializer() {
        return new ChannelRequestX11MessageSerializer(message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }
}
