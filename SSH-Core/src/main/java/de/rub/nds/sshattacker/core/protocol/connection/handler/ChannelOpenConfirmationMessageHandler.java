/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenConfirmationMessageHandler extends Handler<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelOpenConfirmationMessage msg) {
        context.setRemoteChannel(msg.getSenderChannel().getValue());
        // TODO: Set window and packet size for outgoing packets
    }

}
