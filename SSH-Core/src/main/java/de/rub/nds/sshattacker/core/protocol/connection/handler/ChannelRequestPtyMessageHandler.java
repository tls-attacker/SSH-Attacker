/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestPtyMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestPtyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestPtyMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestPtyMessageHandler extends SshMessageHandler<ChannelRequestPtyMessage> {

    public ChannelRequestPtyMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestPtyMessageHandler(SshContext context, ChannelRequestPtyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    @Override
    public ChannelRequestPtyMessageParser getParser(byte[] array) {
        return new ChannelRequestPtyMessageParser(array);
    }

    @Override
    public ChannelRequestPtyMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestPtyMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestPtyMessagePreparator getPreparator() {
        return new ChannelRequestPtyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestPtyMessageSerializer getSerializer() {
        return new ChannelRequestPtyMessageSerializer(message);
    }
}
