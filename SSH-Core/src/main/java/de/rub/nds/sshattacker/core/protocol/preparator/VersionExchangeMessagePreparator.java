/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.preparator;

import de.rub.nds.sshattacker.core.protocol.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VersionExchangeMessagePreparator extends Preparator<VersionExchangeMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public VersionExchangeMessagePreparator(SshContext context, VersionExchangeMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setVersion(context.getChooser().getClientVersion());
        message.setComment(context.getChooser().getClientComment());
        context.appendToExchangeHashInput(message.getIdentification().getBytes());
    }
}
