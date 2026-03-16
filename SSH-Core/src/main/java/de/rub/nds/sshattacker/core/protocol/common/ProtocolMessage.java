/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public abstract class ProtocolMessage<T extends ProtocolMessage<T>>
        extends ModifiableVariableHolder {

    private static final Logger LOGGER = LogManager.getLogger();

    /** resulting message */
    @ModifiableVariableProperty(purpose = ModifiableVariableProperty.Purpose.PLAINTEXT)
    protected ModifiableByteArray completeResultingMessage;

    protected ProtocolMessage() {
        super();
    }

    protected ProtocolMessage(ProtocolMessage<T> other) {
        super();
        completeResultingMessage =
                other.completeResultingMessage != null
                        ? other.completeResultingMessage.createCopy()
                        : null;
    }

    public ModifiableByteArray getCompleteResultingMessage() {
        return completeResultingMessage;
    }

    public void setCompleteResultingMessage(ModifiableByteArray completeResultingMessage) {
        this.completeResultingMessage = completeResultingMessage;
    }

    public void setCompleteResultingMessage(byte[] completeResultingMessage) {
        this.completeResultingMessage =
                ModifiableVariableFactory.safelySetValue(
                        this.completeResultingMessage, completeResultingMessage);
    }

    public abstract T createCopy();

    public abstract byte[] serialize();

    public static ProtocolMessage<?> parse(SshContext context, AbstractPacket packet) {
        ProtocolMessage<?> message = null;
        byte[] raw = packet.getPayload().getValue();
        try {
            if (packet instanceof BlobPacket) {
                String rawText = new String(packet.getPayload().getValue(), StandardCharsets.US_ASCII);
                if (rawText.startsWith("SSH-2.0")) {
                    message = VersionExchangeMessage.parse(context, packet);
                } else {
                    message = AsciiMessage.parse(context, packet);
                }
            }
        }
        return message;
    }

    public abstract String toCompactString();
}
