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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestSignalMessageHandler
        extends SshMessageHandler<ChannelRequestSignalMessage> {

    public ChannelRequestSignalMessageHandler(SshContext context) {
        super(context);
    }

    /*public ChannelRequestSignalMessageHandler(
            SshContext context, ChannelRequestSignalMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ChannelRequestSignalMessage message) {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    /*@Override
    public ChannelRequestSignalMessageParser getParser(byte[] array) {
        return new ChannelRequestSignalMessageParser(array);
    }

    @Override
    public ChannelRequestSignalMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestSignalMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestSignalMessagePreparator getPreparator() {
        return new ChannelRequestSignalMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestSignalMessageSerializer getSerializer() {
        return new ChannelRequestSignalMessageSerializer(message);
    }*/
}
