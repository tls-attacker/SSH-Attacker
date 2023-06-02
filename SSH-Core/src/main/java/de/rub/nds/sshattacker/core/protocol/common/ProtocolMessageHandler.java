/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Handler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageHandler<MessageT extends ProtocolMessage>
        implements Handler<MessageT> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final SshContext sshContext;

    // protected final MessageT message;

    public ProtocolMessageHandler(SshContext sshContext) {
        this.sshContext = sshContext;
    }

    // Kann von den detaillierten Handlern überschrieben werden.
    public void adjustContextAfterSerialize(MessageT message) {}

    /*
        public ProtocolMessageHandler(SshContext context, T message) {
            this.context = context;
            this.message = message;
        }

    */
}
