/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.compressor.PacketCompressor;
import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.packet.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.core.packet.preparator.BinaryPacketPreparator;
import de.rub.nds.sshattacker.core.packet.serializer.BinaryPacketSerializer;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

import java.util.List;
import java.util.Objects;

public class BinaryPacket extends AbstractPacket {

    /**
     * The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    /** The length of the padding. Must be at least 4 bytes and at most 255 bytes to be valid. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableByte paddingLength;

    /** The padding bytes of the packet. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PADDING)
    private ModifiableByteArray padding;

    /** The MAC (or authentication tag if AEAD encryption is used) of the packet. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.HMAC)
    private ModifiableByteArray mac;

    /**
     * The implicit sequence number of this packet which is used in MAC computations as well as
     * SSH_MSG_UNIMPLEMENTED.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger sequenceNumber;

    /** A holder instance for all temporary fields used during crypto computations. */
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

    public ModifiableByte getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(ModifiableByte paddingLength) {
        this.paddingLength = paddingLength;
    }

    public void setPaddingLength(byte paddingLength) {
        this.paddingLength =
                ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public ModifiableByteArray getMac() {
        return mac;
    }

    public void setMac(ModifiableByteArray mac) {
        this.mac = mac;
    }

    public void setMac(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
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
            Chooser chooser, AbstractPacketEncryptor encryptor, PacketCompressor compressor) {
        return new BinaryPacketPreparator(chooser, this, encryptor, compressor);
    }

    @Override
    public BinaryPacketParser getPacketParser(
            byte[] array, int startPosition, PacketCipher activeDecryptCipher, int sequenceNumber) {
        return new BinaryPacketParser(array, startPosition, activeDecryptCipher, sequenceNumber);
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
