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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestBreakMessage;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestBreakMessageHandler
        extends SshMessageHandler<ChannelRequestBreakMessage> {
    public ChannelRequestBreakMessageHandler(SshContext context) {
        super(context);
    }

    /*public ChannelRequestBreakMessageHandler(
            SshContext context, ChannelRequestBreakMessage message) {
        super(context, message);
    }*/

    /*@Override
    public ChannelRequestBreakMessageParser getParser(byte[] array) {
        return new ChannelRequestBreakMessageParser(array);
    }

    @Override
    public ChannelRequestBreakMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestBreakMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestBreakMessagePreparator getPreparator() {
        return new ChannelRequestBreakMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestBreakMessageSerializer getSerializer() {
        return new ChannelRequestBreakMessageSerializer(message);
    }*/

    @Override
    public void adjustContext(ChannelRequestBreakMessage message) {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            sshContext.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }
}
