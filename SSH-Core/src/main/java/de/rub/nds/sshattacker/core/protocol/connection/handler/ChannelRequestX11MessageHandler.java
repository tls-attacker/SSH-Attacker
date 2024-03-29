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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message;
import de.rub.nds.sshattacker.core.util.Converter;

public class ChannelRequestX11MessageHandler extends SshMessageHandler<ChannelRequestX11Message> {
    public ChannelRequestX11MessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ChannelRequestX11Message message) {
        if (Converter.byteToBoolean(message.getWantReply().getValue())) {
            sshContext.getChannelManager().addToChannelRequestResponseQueue(message);
        }
    }
}
