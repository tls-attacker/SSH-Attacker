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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitStatusMessage;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestExitStatusMessageHandler
        extends SshMessageHandler<ChannelRequestExitStatusMessage> {

    public ChannelRequestExitStatusMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelRequestExitStatusMessage message) {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            sshContext.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }
}
