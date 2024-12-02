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
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.data.packet.parser.DataPacketParser;
import de.rub.nds.sshattacker.core.data.packet.preparator.DataPacketPreparator;
import de.rub.nds.sshattacker.core.data.packet.serializer.DataPacketSerializer;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Objects;

/** DataPackets are used for protocols that start with a length field. */
public class DataPacket extends AbstractDataPacket {

    /** The length of the packet in bytes, not including 'packet_length' field itself. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    public DataPacket() {
        super();
    }

    public DataPacket(DataPacket other) {
        super(other);
        length = other.length != null ? other.length.createCopy() : null;
    }

    @Override
    public DataPacket createCopy() {
        return new DataPacket(this);
    }

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public DataPacketPreparator getPacketPreparator(Chooser chooser) {
        return new DataPacketPreparator(chooser, this);
    }

    public DataPacketParser getPacketParser(byte[] array, int startPosition) {
        return new DataPacketParser(array, startPosition);
    }

    @Override
    public DataPacketSerializer getPacketSerializer() {
        return new DataPacketSerializer(this);
    }

    public void prepareComputations() {}

    @Override
    public String toString() {
        return "DataPacket{length=" + length + "}";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        DataPacket that = (DataPacket) obj;
        return Objects.equals(length, that.length)
                && Objects.equals(getPayload(), that.getPayload());
    }

    @Override
    public int hashCode() {
        return Objects.hash(length, getPayload());
    }
}
