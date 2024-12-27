/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.VersionExchangeMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.VersionExchangeMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.VersionExchangeMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class VersionExchangeMessageHandler extends ProtocolMessageHandler<VersionExchangeMessage> {

    public VersionExchangeMessageHandler(SshContext context) {
        super(context);
    }

    public VersionExchangeMessageHandler(SshContext context, VersionExchangeMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (context.isHandleAsClient()) {
            context.setServerVersion(message.getVersion().getValue());
            context.setServerComment(message.getComment().getValue());
            context.getExchangeHashInputHolder().setServerVersion(message);
        } else {
            context.setClientVersion(message.getVersion().getValue());
            context.setClientComment(message.getComment().getValue());
            context.getExchangeHashInputHolder().setClientVersion(message);
        }
    }

    @Override
    public VersionExchangeMessageParser getParser(byte[] array) {
        return new VersionExchangeMessageParser(array);
    }

    @Override
    public VersionExchangeMessageParser getParser(byte[] array, int startPosition) {
        return new VersionExchangeMessageParser(array, startPosition);
    }

    public static final VersionExchangeMessagePreparator PREPARATOR =
            new VersionExchangeMessagePreparator();

    public static final VersionExchangeMessageSerializer SERIALIZER =
            new VersionExchangeMessageSerializer();
}
