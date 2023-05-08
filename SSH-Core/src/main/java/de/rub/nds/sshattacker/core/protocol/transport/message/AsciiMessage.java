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
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.AsciiMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

/**
 * A generic text message sent via the Blob message layer.
 *
 * <p>Examples for this kind of message are the {@code Exceeded MaxStartups} and {@code Invalid SSH
 * identification string} messages sent by OpenSSH.
 */
public class AsciiMessage extends ProtocolMessage<AsciiMessage> {

    private ModifiableString text;
    private ModifiableString endOfMessageSequence;

    public AsciiMessage() {
        super();
    }

    public ModifiableString getText() {
        return this.text;
    }

    public void setText(final ModifiableString text) {
        this.text = text;
    }

    public void setText(final String text) {
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
    public AsciiMessageHandler getHandler(final SshContext context) {
        return new AsciiMessageHandler(context, this);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }
}
