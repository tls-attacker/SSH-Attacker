/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.AsciiMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.AsciiMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class AsciiMessageHandler extends ProtocolMessageHandler<AsciiMessage> {

    public AsciiMessageHandler(final SshContext context) {
        super(context);
    }

    public AsciiMessageHandler(final SshContext context, final AsciiMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        LOGGER.debug("Received text message: {}", this.message.getText().getValue());
    }

    @Override
    public AsciiMessageParser getParser(final byte[] array) {
        return new AsciiMessageParser(array);
    }

    @Override
    public AsciiMessageParser getParser(final byte[] array, final int startPosition) {
        return new AsciiMessageParser(array, startPosition);
    }

    @Override
    public ProtocolMessagePreparator<AsciiMessage> getPreparator() {
        throw new NotImplementedException("AsciiMessageHandler::getPreparator");
    }

    @Override
    public AsciiMessageSerializer getSerializer() {
        return new AsciiMessageSerializer(message);
    }
}
