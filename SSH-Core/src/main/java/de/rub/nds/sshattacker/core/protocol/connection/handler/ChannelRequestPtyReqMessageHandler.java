/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestPtyReqMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestPtyReqMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestPtyReqMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestPtyReqMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestPtyReqMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestPtyReqMessage> {

    @Override
    public ChannelRequestPtyReqMessageParser getParser(byte[] array, SshContext context) {
        return new ChannelRequestPtyReqMessageParser(array);
    }

    @Override
    public ChannelRequestPtyReqMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestPtyReqMessageParser(array, startPosition);
    }

    public static final ChannelRequestPtyReqMessagePreparator PREPARATOR =
            new ChannelRequestPtyReqMessagePreparator();

    public static final ChannelRequestPtyReqMessageSerializer SERIALIZER =
            new ChannelRequestPtyReqMessageSerializer();
}
