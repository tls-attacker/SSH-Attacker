/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.data.packet.parser.AbstractDataPacketParser;
import de.rub.nds.sshattacker.core.data.packet.serializer.AbstractDataPacketSerializer;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

/**
 * AbstractDataPacket are used for packets send over SSH-Channels as ChannelDataMessages
 *
 * <p>AbstractDataPacket do not utilize compression and encryption.
 */
public abstract class AbstractDataPacket extends ModifiableVariableHolder {

    /**
     * This field contains the packet bytes sent over the network. This includes packet_length,
     * padding_length, payload, padding and mac (some fields may be encrypted).
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray completePacketBytes;

    /** The useful contents of the packet. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    private ModifiableByteArray payload;

    protected AbstractDataPacket() {
        super();
    }

    protected AbstractDataPacket(AbstractDataPacket other) {
        super(other);
        completePacketBytes =
                other.completePacketBytes != null ? other.completePacketBytes.createCopy() : null;
        payload = other.payload != null ? other.payload.createCopy() : null;
    }

    @Override
    public abstract AbstractDataPacket createCopy();

    public ModifiableByteArray getCompletePacketBytes() {
        return completePacketBytes;
    }

    public void setCompletePacketBytes(ModifiableByteArray completePacketBytes) {
        this.completePacketBytes = completePacketBytes;
    }

    public void setCompletePacketBytes(byte[] completePacketBytes) {
        this.completePacketBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.completePacketBytes, completePacketBytes);
    }

    public ModifiableByteArray getPayload() {
        return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public abstract void prepare(Chooser chooser);

    public abstract AbstractDataPacketParser<? extends AbstractDataPacket> getPacketParser(
            byte[] array, int startPosition);

    public abstract AbstractDataPacketSerializer<? extends AbstractDataPacket>
            getPacketSerializer();
}
