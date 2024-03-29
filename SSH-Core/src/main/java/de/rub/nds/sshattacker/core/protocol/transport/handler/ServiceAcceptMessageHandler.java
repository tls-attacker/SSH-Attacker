/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceAcceptMessage;

public class ServiceAcceptMessageHandler extends SshMessageHandler<ServiceAcceptMessage> {

    public ServiceAcceptMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(ServiceAcceptMessage message) {
        // TODO: Handle ServiceAcceptMessage
    }
}
