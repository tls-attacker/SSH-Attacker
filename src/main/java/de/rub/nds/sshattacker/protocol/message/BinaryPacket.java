
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.protocol.core.message.Message;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;

public class BinaryPacket extends Message {

    private ModifiableInteger packetLength;
    private ModifiableByte paddingLength;
    private ModifiableByteArray payload;
    private ModifiableByteArray padding;
    private ModifiableByteArray mac;
    
    public BinaryPacket(){
    }
    
    public BinaryPacket(ModifiableByteArray payload){
        this.payload = payload;
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

    public ModifiableByteArray getMac() {
        return mac;
    }

    public void setMac(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }
    
    public void setMac(ModifiableByteArray mac) {
        this.mac = mac;
    }
    
    public void computePacketLength(){
        packetLength = ModifiableVariableFactory.safelySetValue(packetLength,
                payload.getValue().length + paddingLength.getValue()
                        + BinaryPacketConstants.PADDING_FIELD_LENGTH);
    }
    
    public void computePaddingLength(byte blockSize){
        byte excessBytes = (byte) ((payload.getValue().length 
                + BinaryPacketConstants.PADDING_FIELD_LENGTH
                + BinaryPacketConstants.PACKET_FIELD_LENGTH) % blockSize);
        paddingLength = ModifiableVariableFactory.safelySetValue(paddingLength,
                excessBytes == 0 ? 0 : (byte) (blockSize - excessBytes));
    }

    @Override
    public String toCompactString() {
        return "BinaryPacket";
    }
}
