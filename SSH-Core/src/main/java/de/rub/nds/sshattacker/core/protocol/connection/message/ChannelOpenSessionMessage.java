/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenSessionMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenSessionMessage extends ChannelOpenMessage<ChannelOpenSessionMessage> {

    public ChannelOpenSessionMessage() {
        super();
    }

    public ChannelOpenSessionMessage(ChannelOpenSessionMessage other) {
        super(other);
    }

    @Override
    public ChannelOpenSessionMessage createCopy() {
        return new ChannelOpenSessionMessage(this);
    }

    @Override
    public ChannelOpenSessionMessageHandler getHandler(SshContext context) {
        return new ChannelOpenSessionMessageHandler(context, this);
    }
}
