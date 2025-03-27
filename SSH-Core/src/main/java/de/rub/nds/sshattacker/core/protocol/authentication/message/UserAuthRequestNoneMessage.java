/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthRequestNoneMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthRequestNoneMessage extends UserAuthRequestMessage<UserAuthRequestNoneMessage> {

    @Override
    public UserAuthRequestNoneMessageHandler getHandler(SshContext context) {
        return new UserAuthRequestNoneMessageHandler(context, this);
    }
}
