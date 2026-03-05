/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11ReqMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestX11ReqMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestX11ReqMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestX11ReqMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestX11ReqMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestX11ReqMessage> {

    @Override
    public ChannelRequestX11ReqMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestX11ReqMessageParser(array);
    }

    @Override
    public ChannelRequestX11ReqMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestX11ReqMessageParser(array, startPosition);
    }

    public static final ChannelRequestX11ReqMessagePreparator PREPARATOR =
            new ChannelRequestX11ReqMessagePreparator();

    public static final ChannelRequestX11ReqMessageSerializer SERIALIZER =
            new ChannelRequestX11ReqMessageSerializer();
}
