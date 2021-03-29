/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientInitMessagePreparator extends Preparator<ClientInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ClientInitMessagePreparator(SshContext context, ClientInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setVersion(context.getChooser().getClientVersion());
        message.setComment(context.getChooser().getClientComment());
        context.appendToExchangeHashInput(message.getVersion().getValue().getBytes());
    }
}
