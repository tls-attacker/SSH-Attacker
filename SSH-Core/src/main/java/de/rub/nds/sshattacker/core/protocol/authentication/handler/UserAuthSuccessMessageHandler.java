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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthSuccessMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthSuccessMessageHandler extends Handler<UserAuthSuccessMessage> {

    public UserAuthSuccessMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(UserAuthSuccessMessage msg) {
        // TODO: Handle UserAuthSuccessMessageHandler
    }

}
