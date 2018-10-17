
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.protocol.core.message.Parser;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketParser extends Parser<BinaryPacket> {
    
    private static final Logger LOGGER = LogManager.getLogger();

    public BinaryPacketParser(int startPosition, byte[] array){
        super(startPosition, array);
    }
    
    private void parsePacketLength(BinaryPacket msg){
        ModifiableInteger packetLength = ModifiableVariableFactory.safelySetValue(null, parseIntField(4));
        LOGGER.debug("Packet Length: " + packetLength.getValue());
        msg.setPacketLength(packetLength);
    } 
    
    private void parsePaddingLength(BinaryPacket msg){
        ModifiableByte paddingLength = ModifiableVariableFactory.safelySetValue(null, parseByteField(1));
        LOGGER.debug("Padding Length: " + paddingLength.getValue());
        msg.setPaddingLength(paddingLength);
    }
    
    private void parsePayload(BinaryPacket msg){
        int payloadSize = msg.getPacketLength().getValue() - msg.getPaddingLength().getValue() - 1;
        LOGGER.debug("Payload Size: " + payloadSize);
        ModifiableByteArray payload = ModifiableVariableFactory.safelySetValue(null, parseByteArrayField(payloadSize));
        LOGGER.debug("Payload: " + payload);
        msg.setPayload(payload);
    }
    
    private void parsePadding(BinaryPacket msg){
        ModifiableByteArray padding = ModifiableVariableFactory.safelySetValue(null,
                parseByteArrayField(msg.getPaddingLength().getValue()));
        LOGGER.debug("Padding: " + padding);
        msg.setPadding(padding);
    }
    
    private void parseMAC(BinaryPacket msg){
        ModifiableByteArray mac = ModifiableVariableFactory.safelySetValue(null, parseArrayOrTillEnd(-1));
        LOGGER.debug("MAC: " + mac);
        msg.setMac(mac);
    }
    
    @Override
    public BinaryPacket parse() {
        BinaryPacket msg = new BinaryPacket();
        parsePacketLength(msg);
        parsePaddingLength(msg);
        parsePayload(msg);
        parsePadding(msg);
        parseMAC(msg);
        return msg;
    }

}
