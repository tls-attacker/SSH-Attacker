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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestShellMessage;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestShellMessageHandler
        extends SshMessageHandler<ChannelRequestShellMessage> {

    public ChannelRequestShellMessageHandler(SshContext context) {
        super(context);
    }

    /*public ChannelRequestShellMessageHandler(
            SshContext context, ChannelRequestShellMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ChannelRequestShellMessage message) {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            sshContext.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    /*@Override
    public ChannelRequestShellMessageParser getParser(byte[] array) {
        return new ChannelRequestShellMessageParser(array);
    }

    @Override
    public ChannelRequestShellMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestShellMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestShellMessagePreparator getPreparator() {
        return new ChannelRequestShellMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestShellMessageSerializer getSerializer() {
        return new ChannelRequestShellMessageSerializer(message);
    }*/
}
