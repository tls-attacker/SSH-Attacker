/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.NewCompressMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class NewCompressMessage extends SshMessage<NewCompressMessage> {

    @Override
    public NewCompressMessageHandler getHandler(SshContext context) {
        return new NewCompressMessageHandler(context, this);
    }
}
