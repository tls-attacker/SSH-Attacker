/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.IgnoreMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.IgnoreMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.IgnoreMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.IgnoreMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class IgnoreMessageHandler extends SshMessageHandler<IgnoreMessage> {

    @Override
    public void adjustContext(SshContext context, IgnoreMessage object) {}

    @Override
    public IgnoreMessageParser getParser(byte[] array, SshContext context) {
        return new IgnoreMessageParser(array);
    }

    @Override
    public IgnoreMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new IgnoreMessageParser(array, startPosition);
    }

    public static final IgnoreMessagePreparator PREPARATOR = new IgnoreMessagePreparator();

    public static final IgnoreMessageSerializer SERIALIZER = new IgnoreMessageSerializer();
}
