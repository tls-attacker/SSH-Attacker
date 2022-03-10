/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.NoMoreSessionsMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NoMoreSessionsMessage extends GlobalRequestMessage<NoMoreSessionsMessage> {

    private ModifiableByte wantReply;

    public NoMoreSessionsMessage() {
        super(GlobalRequestType.NO_MORE_SESSIONS_OPENSSH_COM);
    }

    @Override
    public NoMoreSessionsMessageHandler getHandler(SshContext context) {
        return new NoMoreSessionsMessageHandler(context, this);
    }
}
