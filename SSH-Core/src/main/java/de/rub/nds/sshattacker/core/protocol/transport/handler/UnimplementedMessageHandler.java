/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.UnimplementedMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.UnimplementedMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnimplementedMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UnimplementedMessageHandler extends SshMessageHandler<UnimplementedMessage> {

    public UnimplementedMessageHandler(SshContext context) {
        super(context);
    }

    public UnimplementedMessageHandler(SshContext context, UnimplementedMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle UnimplementedMessage
    }

    @Override
    public UnimplementedMessageParser getParser(byte[] array, int startPosition) {
        return new UnimplementedMessageParser(array, startPosition);
    }

    @Override
    public UnimplementedMessagePreparator getPreparator() {
        return new UnimplementedMessagePreparator(context.getChooser(), message);
    }

    @Override
    public UnimplementedMessageSerializer getSerializer() {
        return new UnimplementedMessageSerializer(message);
    }
}
