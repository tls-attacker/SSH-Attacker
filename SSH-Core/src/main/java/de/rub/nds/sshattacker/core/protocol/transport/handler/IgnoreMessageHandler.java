/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.IgnoreMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.IgnoreMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.IgnoreMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class IgnoreMessageHandler extends SshMessageHandler<IgnoreMessage> {

    public IgnoreMessageHandler(SshContext context) {
        super(context);
    }

    public IgnoreMessageHandler(SshContext context, IgnoreMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {}

    @Override
    public IgnoreMessageParser getParser(byte[] array) {
        return new IgnoreMessageParser(array);
    }

    @Override
    public IgnoreMessageParser getParser(byte[] array, int startPosition) {
        return new IgnoreMessageParser(array, startPosition);
    }

    @Override
    public IgnoreMessagePreparator getPreparator() {
        return new IgnoreMessagePreparator(context.getChooser(), message);
    }

    @Override
    public IgnoreMessageSerializer getSerializer() {
        return new IgnoreMessageSerializer(message);
    }
}
