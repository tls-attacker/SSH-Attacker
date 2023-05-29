/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthNoneMessage;
import de.rub.nds.sshattacker.core.protocol.common.*;

public class UserAuthNoneMessageHandler extends SshMessageHandler<UserAuthNoneMessage> {

    public UserAuthNoneMessageHandler(SshContext context) {
        super(context);
    }

    /*public UserAuthNoneMessageHandler(SshContext context, UserAuthNoneMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(UserAuthNoneMessage message) {
        // TODO: Handle UserAuthNoneMessage
    }
}
