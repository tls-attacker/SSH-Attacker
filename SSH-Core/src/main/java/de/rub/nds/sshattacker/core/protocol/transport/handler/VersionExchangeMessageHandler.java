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

    @Override
    public void adjustContext(SshContext context, VersionExchangeMessage object) {
        if (context.isHandleAsClient()) {
            context.setServerVersion(object.getVersion().getValue());
            context.setServerComment(object.getComment().getValue());
            context.getExchangeHashInputHolder().setServerVersion(object);
        } else {
            context.setClientVersion(object.getVersion().getValue());
            context.setClientComment(object.getComment().getValue());
            context.getExchangeHashInputHolder().setClientVersion(object);
        }
    }

    @Override
    public VersionExchangeMessageParser getParser(byte[] array, SshContext context) {
        return new VersionExchangeMessageParser(array);
    }

    @Override
    public VersionExchangeMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new VersionExchangeMessageParser(array, startPosition);
    }

    public static final VersionExchangeMessagePreparator PREPARATOR =
            new VersionExchangeMessagePreparator();

    public static final VersionExchangeMessageSerializer SERIALIZER =
            new VersionExchangeMessageSerializer();
}
