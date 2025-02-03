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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

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

    public void setSoftlyText(String text) {
        this.text = ModifiableVariableFactory.softlySetValue(this.text, text);
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

    public void setSoftlyEndOfMessageSequence(String endOfMessageSequence) {
        this.endOfMessageSequence =
                ModifiableVariableFactory.softlySetValue(
                        this.endOfMessageSequence, endOfMessageSequence);
    }

    public static final AsciiMessageHandler HANDLER = new AsciiMessageHandler();

    @Override
    public AsciiMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        AsciiMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return AsciiMessageHandler.SERIALIZER.serialize(this);
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }
}
