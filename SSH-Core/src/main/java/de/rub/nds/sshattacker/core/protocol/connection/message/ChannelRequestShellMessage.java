/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestShellMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestShellMessage extends ChannelRequestMessage<ChannelRequestShellMessage> {

    public ChannelRequestShellMessage() {
        super();
    }

    public ChannelRequestShellMessage(ChannelRequestShellMessage other) {
        super(other);
    }

    @Override
    public ChannelRequestShellMessage createCopy() {
        return new ChannelRequestShellMessage(this);
    }

    @Override
    public ChannelRequestShellMessageHandler getHandler(SshContext context) {
        return new ChannelRequestShellMessageHandler(context, this);
    }
}
