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

import de.rub.nds.sshattacker.protocol.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class GlobalRequestMessageHandler extends Handler<GlobalRequestMessage> {

    public GlobalRequestMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(GlobalRequestMessage msg) {
    }

}
