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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthRequestNoneMessage extends UserAuthRequestMessage<UserAuthRequestNoneMessage> {

    public UserAuthRequestNoneMessage() {
        super();
    }

    public UserAuthRequestNoneMessage(UserAuthRequestNoneMessage other) {
        super(other);
    }

    @Override
    public UserAuthRequestNoneMessage createCopy() {
        return new UserAuthRequestNoneMessage(this);
    }

    public static final UserAuthRequestNoneMessageHandler HANDLER =
            new UserAuthRequestNoneMessageHandler();

    @Override
    public UserAuthRequestNoneMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthRequestNoneMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UserAuthRequestNoneMessageHandler.SERIALIZER.serialize(this);
    }
}
