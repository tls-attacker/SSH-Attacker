/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthSuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthSuccessMessage extends SshMessage<UserAuthSuccessMessage> {

    public UserAuthSuccessMessage() {
        super(MessageIdConstant.SSH_MSG_USERAUTH_SUCCESS);
    }

    @Override
    public UserAuthSuccessMessageHandler getHandler(SshContext context) {
        return new UserAuthSuccessMessageHandler(context, this);
    }
}
