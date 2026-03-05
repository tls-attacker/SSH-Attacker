/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentReqOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestAuthAgentReqOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestAuthAgentReqOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestAuthAgentReqOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestAuthAgentReqOpenSshMessageHandler
        extends ChannelRequestMessageHandler<ChannelRequestAuthAgentReqOpenSshMessage> {

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessageParser getParser(
            byte[] array, SshContext context) {
        return new ChannelRequestAuthAgentReqOpenSshMessageParser(array);
    }

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ChannelRequestAuthAgentReqOpenSshMessageParser(array, startPosition);
    }

    public static final ChannelRequestAuthAgentReqOpenSshMessagePreparator PREPARATOR =
            new ChannelRequestAuthAgentReqOpenSshMessagePreparator();

    public static final ChannelRequestAuthAgentReqOpenSshMessageSerializer SERIALIZER =
            new ChannelRequestAuthAgentReqOpenSshMessageSerializer();
}
