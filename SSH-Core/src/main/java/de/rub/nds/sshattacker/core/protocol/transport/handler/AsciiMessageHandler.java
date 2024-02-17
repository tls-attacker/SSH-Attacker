/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;

public class AsciiMessageHandler extends ProtocolMessageHandler<AsciiMessage> {

    public AsciiMessageHandler(SshContext context) {
        super(context);
    }

    /*public AsciiMessageHandler(SshContext context, AsciiMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(AsciiMessage message) {
        LOGGER.debug(
                "Received text message: {}", backslashEscapeString(message.getText().getValue()));
    }

    /*
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
        return new AsciiMessagePreparator(context.getChooser(), message);
    }

    @Override
    public AsciiMessageSerializer getSerializer() {
        return new AsciiMessageSerializer(message);
    }
    */
}
