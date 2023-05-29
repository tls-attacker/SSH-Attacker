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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestEnvMessage;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestEnvMessageHandler extends SshMessageHandler<ChannelRequestEnvMessage> {

    public ChannelRequestEnvMessageHandler(SshContext context) {
        super(context);
    }

    /*public ChannelRequestEnvMessageHandler(SshContext context, ChannelRequestEnvMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(ChannelRequestEnvMessage message) {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            context.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }

    /*@Override
    public ChannelRequestEnvMessageParser getParser(byte[] array) {
        return new ChannelRequestEnvMessageParser(array);
    }

    @Override
    public ChannelRequestEnvMessageParser getParser(byte[] array, int startPosition) {
        return new ChannelRequestEnvMessageParser(array, startPosition);
    }

    @Override
    public ChannelRequestEnvMessagePreparator getPreparator() {
        return new ChannelRequestEnvMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ChannelRequestEnvMessageSerializer getSerializer() {
        return new ChannelRequestEnvMessageSerializer(message);
    }*/
}
