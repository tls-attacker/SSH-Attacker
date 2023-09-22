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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.DataContainer;
import de.rub.nds.sshattacker.core.layer.data.Handler;
import de.rub.nds.sshattacker.core.packet.parser.BinaryPacketParserSSHv1;
import de.rub.nds.sshattacker.core.packet.preparator.BinaryPacketPreparatorSSHv1;
import de.rub.nds.sshattacker.core.packet.serializer.BinaryPacketSerializerSSHv1;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import java.io.InputStream;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketSSHv1 extends AbstractPacket<BinaryPacketSSHv1>
        implements DataContainer<BinaryPacketSSHv1, SshContext> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger length;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_RECORD)
    private ModifiableByteArray CrcChecksum;

    /** The length of the padding. Must be at least 4 bytes and at most 255 bytes to be valid. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger paddingLength;

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

    public BinaryPacketSSHv1() {}

    public ModifiableInteger getLength() {
        return length;
    }

    public void setLength(ModifiableInteger length) {
        this.length = length;
    }

    public void setLength(int length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableInteger getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(ModifiableInteger paddingLength) {
        this.paddingLength = paddingLength;
    }

    public void setPaddingLength(int paddingLength) {
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

    public PacketCryptoComputations getComputations() {
        return computations;
    }

    public void setComputations(PacketCryptoComputations computations) {
        this.computations = computations;
    }

    public ModifiableByteArray getCrcChecksum() {
        return CrcChecksum;
    }

    public void setCrcChecksum(ModifiableByteArray crcChecksum) {
        CrcChecksum = crcChecksum;
    }

    public void setCrcChecksum(byte[] crcChecksum) {
        CrcChecksum = ModifiableVariableFactory.safelySetValue(this.CrcChecksum, crcChecksum);
    }

    @Override
    public void prepareComputations() {
        LOGGER.info("[bro] Preparing Computation");
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
        BinaryPacketSSHv1 that = (BinaryPacketSSHv1) o;
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

    @Override
    public BinaryPacketParserSSHv1 getParser(SshContext context, InputStream stream) {
        return new BinaryPacketParserSSHv1(
                stream, context.getActiveDecryptCipher(), sequenceNumber.getValue());
    }

    @Override
    public BinaryPacketPreparatorSSHv1 getPreparator(SshContext context) {
        return new BinaryPacketPreparatorSSHv1(
                context.getChooser(),
                this,
                context.getPacketLayer().getEncryptor(),
                context.getCompressor());
    }

    @Override
    public BinaryPacketSerializerSSHv1 getSerializer(SshContext context) {
        return new BinaryPacketSerializerSSHv1(this);
    }

    @Override
    public Handler getHandler(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
