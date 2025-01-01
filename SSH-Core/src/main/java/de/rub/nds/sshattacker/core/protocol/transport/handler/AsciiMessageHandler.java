/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.AsciiMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.AsciiMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.AsciiMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class AsciiMessageHandler extends ProtocolMessageHandler<AsciiMessage> {

    @Override
    public void adjustContext(SshContext context, AsciiMessage object) {
        LOGGER.debug(
                "Received text message: {}",
                () -> backslashEscapeString(object.getText().getValue()));
    }

    @Override
    public AsciiMessageParser getParser(byte[] array, SshContext context) {
        return new AsciiMessageParser(array);
    }

    @Override
    public AsciiMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new AsciiMessageParser(array, startPosition);
    }

    public static final AsciiMessagePreparator PREPARATOR = new AsciiMessagePreparator();

    public static final AsciiMessageSerializer SERIALIZER = new AsciiMessageSerializer();
}
