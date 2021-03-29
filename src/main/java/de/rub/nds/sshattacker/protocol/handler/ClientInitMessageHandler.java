/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.state.SshContext;

import java.util.Objects;

public class ClientInitMessageHandler extends Handler<ClientInitMessage> {

    public ClientInitMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(ClientInitMessage message) {
        context.setServerVersion(message.getVersion().getValue());
        context.setServerComment(message.getComment().getValue());
        context.appendToExchangeHashInput(Objects.requireNonNull(context.getServerVersion().orElse(null)).getBytes());
    }
}
