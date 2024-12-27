/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthNoneMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthNoneMessage extends UserAuthRequestMessage<UserAuthNoneMessage> {

    public UserAuthNoneMessage() {
        super();
    }

    public UserAuthNoneMessage(UserAuthNoneMessage other) {
        super(other);
    }

    @Override
    public UserAuthNoneMessage createCopy() {
        return new UserAuthNoneMessage(this);
    }

    @Override
    public UserAuthNoneMessageHandler getHandler(SshContext context) {
        return new UserAuthNoneMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthNoneMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
