/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestAuthAgentMessage;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestAuthAgentMessageHandler
        extends SshMessageHandler<ChannelRequestAuthAgentMessage> {

    public ChannelRequestAuthAgentMessageHandler(SshContext context) {
        super(context);
    }

    /*public ChannelRequestAuthAgentMessageHandler(
            SshContext context, ChannelRequestAuthAgentMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ChannelRequestAuthAgentMessage message) {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    /*@Override
    public ChannelRequestAuthAgentMessageParser getParser(byte[] array) {
        return new ChannelRequestAuthAgentMessageParser(array);
    }

    @Override
    public ChannelRequestAuthAgentMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestAuthAgentMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestAuthAgentMessagePreparator getPreparator() {
        return new ChannelRequestAuthAgentMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestAuthAgentMessageSerializer getSerializer() {
        return new ChannelRequestAuthAgentMessageSerializer(message);
    }*/
}
