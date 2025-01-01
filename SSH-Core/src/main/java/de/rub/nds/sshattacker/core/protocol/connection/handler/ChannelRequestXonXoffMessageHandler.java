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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestXonXoffMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestXonXoffMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestXonXoffMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestXonXoffMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestXonXoffMessageHandler
        extends SshMessageHandler<ChannelRequestXonXoffMessage>
        implements MessageSentHandler<ChannelRequestXonXoffMessage> {

    @Override
    public void adjustContext(SshContext context, ChannelRequestXonXoffMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addReceivedRequestThatWantsReply(object);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(
            SshContext context, ChannelRequestXonXoffMessage object) {
        if (Converter.byteToBoolean(object.getWantReply().getValue())) {
            // This should not happen, because WantReply should always be false
            context.getChannelManager().addSentRequestThatWantsReply(object);
        }
    }

    @Override
    public ChannelRequestXonXoffMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestXonXoffMessageParser(array);
    }

    @Override
    public ChannelRequestXonXoffMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestXonXoffMessageParser(array, startPosition);
    }

    public static final ChannelRequestXonXoffMessagePreparator PREPARATOR =
            new ChannelRequestXonXoffMessagePreparator();

    public static final ChannelRequestXonXoffMessageSerializer SERIALIZER =
            new ChannelRequestXonXoffMessageSerializer();
}
