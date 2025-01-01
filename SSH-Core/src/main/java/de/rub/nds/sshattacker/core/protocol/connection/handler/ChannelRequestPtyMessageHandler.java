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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestPtyMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestPtyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestPtyMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestPtyMessageHandler extends SshMessageHandler<ChannelRequestPtyMessage>
        implements MessageSentHandler<ChannelRequestPtyMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestPtyMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(SshContext context, ChannelRequestPtyMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestPtyMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestPtyMessageParser(array);
    }

    @Override
    public ChannelRequestPtyMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestPtyMessageParser(array, startPosition);
    }

    public static final ChannelRequestPtyMessagePreparator PREPARATOR =
            new ChannelRequestPtyMessagePreparator();

    public static final ChannelRequestPtyMessageSerializer SERIALIZER =
            new ChannelRequestPtyMessageSerializer();
}
