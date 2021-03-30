/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.handler;

import de.rub.nds.sshattacker.core.protocol.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelExtendedDataMessageHandler extends Handler<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ChannelExtendedDataMessage msg) {
    }

}
