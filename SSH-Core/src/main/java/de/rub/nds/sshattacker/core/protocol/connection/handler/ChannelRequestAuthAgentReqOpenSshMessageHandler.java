/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentReqOpenSshMessage;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestAuthAgentReqOpenSshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestAuthAgentReqOpenSshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestAuthAgentReqOpenSshMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestAuthAgentReqOpenSshMessageHandler
        extends SshMessageHandler<ChannelRequestAuthAgentReqOpenSshMessage> {

    public ChannelRequestAuthAgentReqOpenSshMessageHandler(SshContext context) {
        super(context);
    }

    public ChannelRequestAuthAgentReqOpenSshMessageHandler(
            SshContext context, ChannelRequestAuthAgentReqOpenSshMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle ChannelRequestAuthAgentReqOpenSshMessage
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessageParser getParser(byte[] array) {
        return new ChannelRequestAuthAgentReqOpenSshMessageParser(array);
    }

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessageParser getParser(
            byte[] array, int startPosition) {
        return new ChannelRequestAuthAgentReqOpenSshMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessagePreparator getPreparator() {
        return new ChannelRequestAuthAgentReqOpenSshMessagePreparator(
                context.getChooser(), message);
    }

    @Override
    public ChannelRequestAuthAgentReqOpenSshMessageSerializer getSerializer() {
        return new ChannelRequestAuthAgentReqOpenSshMessageSerializer(message);
    }
}
