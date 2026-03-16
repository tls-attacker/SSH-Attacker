/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.protocol.common.OnMessageParsed;
import de.rub.nds.sshattacker.core.protocol.common.OnPrepare;
import de.rub.nds.sshattacker.core.protocol.common.OnReceive;
import de.rub.nds.sshattacker.core.protocol.common.ParserStream;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.AsciiMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

/**
 * A generic text message sent via the Blob message layer.
 *
 * <p>Examples for this kind of message are the {@code Exceeded MaxStartups} and {@code Invalid SSH
 * identification string} messages sent by OpenSSH.
 */
public class AsciiMessage extends ProtocolMessage<AsciiMessage> implements OnPrepare, OnReceive {

    private static final Logger LOGGER = LogManager.getLogger();

    private ModifiableString text;
    private ModifiableString endOfMessageSequence;

    public AsciiMessage() {
        super();
    }

    public AsciiMessage(AsciiMessage other) {
        super(other);
        text = other.text != null ? other.text.createCopy() : null;
        endOfMessageSequence =
                other.endOfMessageSequence != null ? other.endOfMessageSequence.createCopy() : null;
    }

    @Override
    public AsciiMessage createCopy() {
        return new AsciiMessage(this);
    }

    public ModifiableString getText() {
        return text;
    }

    public void setText(ModifiableString text) {
        this.text = text;
    }

    public void setText(String text) {
        this.text = ModifiableVariableFactory.safelySetValue(this.text, text);
    }

    public ModifiableString getEndOfMessageSequence() {
        return endOfMessageSequence;
    }

    public void setEndOfMessageSequence(ModifiableString endOfMessageSequence) {
        this.endOfMessageSequence = endOfMessageSequence;
    }

    public void setEndOfMessageSequence(String endOfMessageSequence) {
        this.endOfMessageSequence =
                ModifiableVariableFactory.safelySetValue(
                        this.endOfMessageSequence, endOfMessageSequence);
    }

    @Override
    public void onReceive(SshContext context) {
        String messageText = text.getValue();
        LOGGER.debug(
                "Received text message: {}",
                () -> backslashEscapeString(messageText));
        if ("Invalid SSH identification string.".equals(messageText)) {
            LOGGER.warn(
                    "The server reported the identification string sent by the SSH-Attacker is invalid");
        } else if ("Exceeded MaxStartups".equals(messageText)) {
            LOGGER.warn(
                    "The server reported the maximum number of concurrent unauthenticated connections has been exceeded.");
        }
    }

    @Override
    public byte[] serialize() {
        return AsciiMessageHandler.SERIALIZER.serialize(this);
    }

    public static AsciiMessage parse(SshContext context, byte[] raw) throws IOException {
        return parse(context, raw, 0);
    }

    public static AsciiMessage parse(SshContext context, byte[] raw, int startPosition) throws IOException {
        ParserStream parserStream = new ParserStream(raw, startPosition);
        AsciiMessage message = new AsciiMessage();
        String text = parserStream.readStringUntil(CharConstants.NEWLINE);
        if (text.endsWith("\r\n")) {
            message.setEndOfMessageSequence("\r\n");
            text = text.substring(0, text.length() - 2);
        } else if (text.endsWith("\n")) {
            message.setEndOfMessageSequence("\n");
            text = text.substring(0, text.length() - 1);
        } else if (text.endsWith("\r")) {
            message.setEndOfMessageSequence("\r");
            text = text.substring(0, text.length() - 1);
        } else {
            message.setEndOfMessageSequence("");
        }
        message.setText(text);
        return message;
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }

    @Override
    public void onPrepare(SshContext context) {

    }
}
