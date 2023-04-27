/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AsciiMessageParser extends ProtocolMessageParser<AsciiMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AsciiMessageParser(final byte[] array) {
        super(array);
    }

    public AsciiMessageParser(final byte[] array, final int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected AsciiMessage createMessage() {
        return new AsciiMessage();
    }

    private void parseText() {
        // parse till CR NL (and remove them)
        String result = this.parseStringTill(new byte[] {CharConstants.NEWLINE});
        if (result.endsWith("\r\n")) {
            message.setEndOfMessageSequence("\r\n");
            result = result.substring(0, result.length() - 2);
        } else if (result.endsWith("\n")) {
            message.setEndOfMessageSequence("\n");
            result = result.substring(0, result.length() - 1);
        } else {
            // This may happen if the server sends a malformed message.
            message.setEndOfMessageSequence("");
        }

        message.setText(result);
    }

    @Override
    public void parseProtocolMessageContents() {
        parseText();
    }
}
