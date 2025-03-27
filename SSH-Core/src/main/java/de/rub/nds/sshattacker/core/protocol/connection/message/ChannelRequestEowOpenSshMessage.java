/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestEowOpenSshMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelRequestEowOpenSshMessage
        extends ChannelRequestMessage<ChannelRequestEowOpenSshMessage> {

    @Override
    public ChannelRequestEowOpenSshMessageHandler getHandler(SshContext context) {
        return new ChannelRequestEowOpenSshMessageHandler(context, this);
    }
}
