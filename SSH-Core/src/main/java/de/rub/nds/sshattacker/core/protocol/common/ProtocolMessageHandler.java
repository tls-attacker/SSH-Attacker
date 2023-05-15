/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.state.SshContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageHandler<T extends ProtocolMessage<T>> implements Handler<T> {

    protected static final Logger LOGGER = LogManager.getLogger();

    protected final SshContext context;

    protected final T message;

    protected ProtocolMessageHandler(SshContext context) {
        this(context, null);
    }

    protected ProtocolMessageHandler(SshContext context, T message) {
        super();
        this.context = context;
        this.message = message;
    }

    @Override
    public abstract ProtocolMessageParser<T> getParser(byte[] array);

    @Override
    public abstract ProtocolMessageParser<T> getParser(byte[] array, int startPosition);

    @Override
    public abstract ProtocolMessagePreparator<T> getPreparator();

    @Override
    public abstract ProtocolMessageSerializer<T> getSerializer();
}
