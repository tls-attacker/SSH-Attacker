/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11ReqMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestX11ReqMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestX11ReqMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestX11ReqMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestX11ReqMessageHandler
        extends SshMessageHandler<ChannelRequestX11ReqMessage> {
    public ChannelRequestX11ReqMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestX11ReqMessageHandler(
            SshContext context, ChannelRequestX11ReqMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelRequestX11ReqMessage
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    @Override
    public ChannelRequestX11ReqMessageParser getParser(byte[] array) {
        return new ChannelRequestX11ReqMessageParser(array);
    }

    @Override
    public ChannelRequestX11ReqMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestX11ReqMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestX11ReqMessagePreparator getPreparator() {
        return new ChannelRequestX11ReqMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestX11ReqMessageSerializer getSerializer() {
        return new ChannelRequestX11ReqMessageSerializer(message);
    }
}
