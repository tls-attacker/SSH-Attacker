/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Parser;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.*;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ProtocolMessageParser<T extends ProtocolMessage<T>> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    // protected final T message = createMessage();

    protected ProtocolMessageParser(InputStream stream) {
        super(stream);
    }

    public static ProtocolMessage<?> delegateParsing(AbstractPacket packet, SshContext context) {
        byte[] raw = packet.getPayload().getValue();
        try {
            if (packet instanceof BlobPacket) {
                String rawText =
                        new String(packet.getPayload().getValue(), StandardCharsets.US_ASCII);
                if (rawText.startsWith("SSH-2.0")) {
                    VersionExchangeMessage message = new VersionExchangeMessage();
                    VersionExchangeMessageParser parser =
                            new VersionExchangeMessageParser(new ByteArrayInputStream(raw));
                    parser.parse(message);
                    return message;
                } else {
                    AsciiMessage message = new AsciiMessage();
                    AsciiMessageParser parser =
                            new AsciiMessageParser(new ByteArrayInputStream(raw));
                    parser.parse(message);

                    // If we know what the text message means we can print a
                    // human-readable warning to the log. The following
                    // messages are sent by OpenSSH.
                    String messageText = message.getText().getValue();
                    if ("Invalid SSH identification string.".equals(messageText)) {
                        LOGGER.warn(
                                "The server reported the identification string sent by the SSH-Attacker is invalid");
                    } else if ("Exceeded MaxStartups".equals(messageText)) {
                        LOGGER.warn(
                                "The server reported the maximum number of concurrent unauthenticated connections has been exceeded.");
                    }
                    return message;
                }
            }

        } catch (ParserException e) {
            LOGGER.debug("Error while Parsing, now parsing as UnknownMessage: " + e);
            // return new UnknownMessageParser(raw).parse();
        }
        return null;
    }
}
