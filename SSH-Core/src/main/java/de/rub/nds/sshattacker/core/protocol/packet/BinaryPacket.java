/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.crypto.packet.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.crypto.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.packet.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.core.protocol.packet.preparator.BinaryPacketPreparator;
import de.rub.nds.sshattacker.core.protocol.packet.serializer.BinaryPacketSerializer;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.List;
import java.util.Objects;

public class BinaryPacket extends AbstractPacket {

    /**
     * The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    /**
     * The implicit sequence number of this packet which is used in MAC computations as well as
     * SSH_MSG_UNIMPLEMENTED.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger sequenceNumber;

    /**
     * A holder instance for all crypto related fields. This includes padding, keys, mac,
     * ciphertext, ...
     */
    private PacketCryptoComputations computations;

    public BinaryPacket() {}

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableInteger getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(ModifiableInteger sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber =
                ModifiableVariableFactory.safelySetValue(this.sequenceNumber, sequenceNumber);
    }

    @Override
    public BinaryPacketPreparator getPacketPreparator(
            Chooser chooser, AbstractPacketEncryptor encryptor) {
        return new BinaryPacketPreparator(chooser, this, encryptor);
    }

    @Override
    public BinaryPacketParser getPacketParser(
            byte[] array, int startPosition, PacketCipher activeDecryptCipher) {
        return new BinaryPacketParser(array, startPosition, activeDecryptCipher);
    }

    @Override
    public BinaryPacketSerializer getPacketSerializer() {
        return new BinaryPacketSerializer(this);
    }

    public PacketCryptoComputations getComputations() {
        return computations;
    }

    public void setComputations(PacketCryptoComputations computations) {
        this.computations = computations;
    }

    @Override
    public void prepareComputations() {
        if (computations == null) {
            computations = new PacketCryptoComputations();
        }
    }

    @Override
    public String toString() {
        return "BinaryPacket{length=" + length + "}";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BinaryPacket that = (BinaryPacket) o;
        return Objects.equals(length, that.length)
                && Objects.equals(sequenceNumber, that.sequenceNumber)
                && Objects.equals(computations, that.computations);
    }

    @Override
    public int hashCode() {
        return Objects.hash(length, sequenceNumber, computations);
    }

    @Override
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = super.getAllModifiableVariableHolders();
        if (computations != null) {
            holders.add(computations);
        }
        return holders;
    }
}
