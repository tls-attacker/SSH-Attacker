/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.NewKeysMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class NewKeysMessage extends SshMessage<NewKeysMessage> {

    public NewKeysMessage() {
        super();
    }

    public NewKeysMessage(NewKeysMessage other) {
        super(other);
    }

    @Override
    public NewKeysMessage createCopy() {
        return new NewKeysMessage(this);
    }

    @Override
    public NewKeysMessageHandler getHandler(SshContext context) {
        return new NewKeysMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        NewKeysMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
