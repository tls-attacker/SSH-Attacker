/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.packet;

import de.rub.nds.sshattacker.core.data.packet.parser.PassThroughPacketParser;
import de.rub.nds.sshattacker.core.data.packet.preparator.PassThroughPacketPreparator;
import de.rub.nds.sshattacker.core.data.packet.serializer.PassThroughPacketSerializer;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Objects;

/**
 * PassThroughPackets are used for data that does not have any packet structure. It just passes the
 * data as is to the next layer.
 */
public class PassThroughPacket extends AbstractDataPacket {

    public PassThroughPacket() {
        super();
    }

    public PassThroughPacket(PassThroughPacket other) {
        super(other);
    }

    @Override
    public PassThroughPacket createCopy() {
        return new PassThroughPacket(this);
    }

    public PassThroughPacketPreparator getPacketPreparator(Chooser chooser) {
        return new PassThroughPacketPreparator(chooser, this);
    }

    public PassThroughPacketParser getPacketParser(byte[] array, int startPosition) {
        return new PassThroughPacketParser(array, startPosition);
    }

    @Override
    public PassThroughPacketSerializer getPacketSerializer() {
        return new PassThroughPacketSerializer(this);
    }

    @Override
    public String toString() {
        return "PassThroughPacket";
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        PassThroughPacket that = (PassThroughPacket) obj;
        return Objects.equals(getPayload(), that.getPayload());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getPayload());
    }
}
