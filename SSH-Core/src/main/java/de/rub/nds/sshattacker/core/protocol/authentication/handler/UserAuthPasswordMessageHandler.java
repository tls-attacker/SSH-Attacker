/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPasswordMessageHandler extends Handler<UserAuthPasswordMessage> {

    public UserAuthPasswordMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UserAuthPasswordMessage msg) {
        // TODO: Handle UserAuthPasswordMessage
    }

}
