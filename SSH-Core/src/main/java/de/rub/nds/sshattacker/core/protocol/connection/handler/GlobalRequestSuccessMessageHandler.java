/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage;

public class GlobalRequestSuccessMessageHandler
        extends SshMessageHandler<GlobalRequestSuccessMessage> {

    public GlobalRequestSuccessMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(GlobalRequestSuccessMessage message) {
        // TODO: Handle RequestSucessMessage
    }
}
