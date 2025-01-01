/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestX11MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestX11MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestX11MessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestX11MessageHandler extends SshMessageHandler<ChannelRequestX11Message>
        implements MessageSentHandler<ChannelRequestX11Message> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestX11Message object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(SshContext context, ChannelRequestX11Message object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestX11MessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestX11MessageParser(array);
    }

    @Override
    public ChannelRequestX11MessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestX11MessageParser(array, startPosition);
    }

    public static final ChannelRequestX11MessagePreparator PREPARATOR =
            new ChannelRequestX11MessagePreparator();

    public static final ChannelRequestX11MessageSerializer SERIALIZER =
            new ChannelRequestX11MessageSerializer();
}
