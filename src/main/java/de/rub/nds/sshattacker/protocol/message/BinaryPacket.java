/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.state.SshContext;

public class BinaryPacket extends Message<BinaryPacket> {

    private ModifiableInteger packetLength;
    private ModifiableByte paddingLength;
    private ModifiableByteArray payload;
    private ModifiableByteArray padding;
    private ModifiableByteArray mac;

    public BinaryPacket() {
    }

    public BinaryPacket(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public BinaryPacket(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(null, payload);
    }

    public ModifiableInteger getPacketLength() {
        return packetLength;
    }

    public void setPacketLength(int packetLength) {
        this.packetLength = ModifiableVariableFactory.safelySetValue(this.packetLength, packetLength);
    }

    public void setPacketLength(ModifiableInteger packetLength) {
        this.packetLength = packetLength;
    }

    public ModifiableByte getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(byte paddingLength) {
        this.paddingLength = ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    public void setPaddingLength(ModifiableByte paddingLength) {
        this.paddingLength = paddingLength;
    }

    public ModifiableByteArray getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public void setPayload(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void generatePadding() {
        setPadding(new byte[getPaddingLength().getValue()]);
    }

    public ModifiableByteArray getMac() {
        return mac;
    }

    public void setMac(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }

    public void setMac(ModifiableByteArray mac) {
        this.mac = mac;
    }

    public void computePacketLength() {
        packetLength = ModifiableVariableFactory.safelySetValue(packetLength,
                payload.getValue().length + paddingLength.getValue() + BinaryPacketConstants.PADDING_FIELD_LENGTH);
    }

    public void computePaddingLength(byte blockSize) {
        // packetLength has to be divisible by 8 or blockSize whichever is
        // greater
        if (blockSize < 8) {
            blockSize = 8;
        }

        byte excessBytes = (byte) ((payload.getValue().length + BinaryPacketConstants.PADDING_FIELD_LENGTH + BinaryPacketConstants.PACKET_FIELD_LENGTH) % blockSize);

        byte intermediatePaddingLength = (byte) (blockSize - excessBytes);
        if (intermediatePaddingLength < 4) {
            intermediatePaddingLength += blockSize;
        }
        paddingLength = ModifiableVariableFactory.safelySetValue(paddingLength, intermediatePaddingLength);
    }

    @Override
    public Handler<BinaryPacket> getHandler(SshContext context) {
        return null;
    }

    @Override
    public Serializer<BinaryPacket> getSerializer() {
        return null;
    }

    @Override
    public Preparator<BinaryPacket> getPreparator(SshContext context) {
        return null;
    }

    @Override
    public String toCompactString() {
        return "BinaryPacket";
    }
}
