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
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;

public class VersionExchangeMessageHandler extends ProtocolMessageHandler<VersionExchangeMessage> {

    public VersionExchangeMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(VersionExchangeMessage message) {
        if (sshContext.isHandleAsClient()) {
            sshContext.setServerVersion(message.getVersion().getValue());
            sshContext.setServerComment(message.getComment().getValue());
            sshContext.getExchangeHashInputHolder().setServerVersion(message);
        } else {
            sshContext.setClientVersion(message.getVersion().getValue());
            sshContext.setClientComment(message.getComment().getValue());
            sshContext.getExchangeHashInputHolder().setClientVersion(message);
        }
    }
}
