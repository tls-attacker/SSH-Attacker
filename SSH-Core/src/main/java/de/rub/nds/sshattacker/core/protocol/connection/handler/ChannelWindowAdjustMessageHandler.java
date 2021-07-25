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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelWindowAdjustMessageHandler extends Handler<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelWindowAdjustMessage msg) {
        // TODO: Handle ChannelWindowAdjustMessageHandler
    }

}
