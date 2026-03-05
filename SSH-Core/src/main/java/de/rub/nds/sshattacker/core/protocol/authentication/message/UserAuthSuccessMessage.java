/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthSuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthSuccessMessage extends SshMessage<UserAuthSuccessMessage>
        implements HasSentHandler {

    public UserAuthSuccessMessage() {
        super();
    }

    public UserAuthSuccessMessage(UserAuthSuccessMessage other) {
        super(other);
    }

    @Override
    public UserAuthSuccessMessage createCopy() {
        return new UserAuthSuccessMessage(this);
    }

    public static final UserAuthSuccessMessageHandler HANDLER = new UserAuthSuccessMessageHandler();

    @Override
    public UserAuthSuccessMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UserAuthSuccessMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return UserAuthSuccessMessageHandler.SERIALIZER.serialize(this);
    }
}
