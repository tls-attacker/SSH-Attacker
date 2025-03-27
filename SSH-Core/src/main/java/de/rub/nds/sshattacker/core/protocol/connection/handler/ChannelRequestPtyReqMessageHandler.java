/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyReqMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestPtyReqMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestPtyReqMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestPtyReqMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestPtyReqMessageHandler
        extends SshMessageHandler<ChannelRequestPtyReqMessage> {

    public ChannelRequestPtyReqMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestPtyReqMessageHandler(
            SshContext context, ChannelRequestPtyReqMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelRequestPtyReqMessage
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    @Override
    public ChannelRequestPtyReqMessageParser getParser(byte[] array) {
        return new ChannelRequestPtyReqMessageParser(array);
    }

    @Override
    public ChannelRequestPtyReqMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestPtyReqMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestPtyReqMessagePreparator getPreparator() {
        return new ChannelRequestPtyReqMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestPtyReqMessageSerializer getSerializer() {
        return new ChannelRequestPtyReqMessageSerializer(message);
    }
}
