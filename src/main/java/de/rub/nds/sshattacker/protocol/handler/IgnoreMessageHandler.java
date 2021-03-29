/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class IgnoreMessageHandler extends Handler<IgnoreMessage> {

    public IgnoreMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(IgnoreMessage msg) {
    }

}
