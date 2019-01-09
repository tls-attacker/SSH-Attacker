package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.protocol.core.message.Parser;
import de.rub.nds.sshattacker.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.constants.MessageIDConstants;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class BinaryPacketParser<T extends BinaryPacket> extends Parser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public BinaryPacketParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseMessageID(BinaryPacket msg) {
        msg.setMessageID(parseByteField(BinaryPacketConstants.MESSAGE_ID_LENGTH));
        LOGGER.debug("Message ID: " + msg.getMessageID().getValue());
    }

    private void parsePacketLength(BinaryPacket msg) {
        ModifiableInteger packetLength = ModifiableVariableFactory.safelySetValue(null, parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Packet Length: " + packetLength.getValue());
        msg.setPacketLength(packetLength);
    }

    private void parsePaddingLength(BinaryPacket msg) {
        ModifiableByte paddingLength = ModifiableVariableFactory.safelySetValue(null, parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        LOGGER.debug("Padding Length: " + paddingLength.getValue());
        msg.setPaddingLength(paddingLength);
    }

    private void parsePayload(BinaryPacket msg) {
        int payloadSize = msg.getPacketLength().getValue() - msg.getPaddingLength().getValue() - BinaryPacketConstants.PADDING_FIELD_LENGTH - BinaryPacketConstants.MESSAGE_ID_LENGTH;
        LOGGER.debug("Payload Size: " + payloadSize);
        ModifiableByteArray payload = ModifiableVariableFactory.safelySetValue(null, parseByteArrayField(payloadSize));
        LOGGER.debug("Payload: " + payload);
        msg.setPayload(payload);
    }

    private void parsePadding(BinaryPacket msg) {
        ModifiableByteArray padding = ModifiableVariableFactory.safelySetValue(null,
                parseByteArrayField(msg.getPaddingLength().getValue()));
        LOGGER.debug("Padding: " + padding);
        msg.setPadding(padding);
    }

    private void parseMAC(BinaryPacket msg) {
        ModifiableByteArray mac = ModifiableVariableFactory.safelySetValue(null, parseArrayOrTillEnd(-1));
        if (mac.getValue().length == 0) {
            LOGGER.debug("MAC: none");
            msg.setMac((byte[]) null);
        } else {
            LOGGER.debug("MAC: " + mac);
            msg.setMac(mac);
        }
    }
    
    public static BinaryPacket delegateParsing(byte[] raw){
        byte messageID = raw[5];
        switch (messageID){
            case MessageIDConstants.SSH_MSG_KEXINIT: return new KeyExchangeInitMessageParser(0, raw).parse();
            case MessageIDConstants.SSH_MSG_KEX_ECDH_INIT: return new ECDHKeyExchangeInitMessageParser(0, raw).parse();
            case MessageIDConstants.SSH_MSG_KEX_ECDH_REPLY: return new ECDHKeyExchangeReplyMessageParser(0, raw).parse();
            case MessageIDConstants.SSH_MSG_NEWKEYS: return // TODO what to do with newkeys? derive a new binarypacket instance?
            default: LOGGER.debug("Unknown MessageID: " + messageID);
                     return null;
        }
    }

    @Override
    public T parse() {
        T msg = createMessage();
        parsePacketLength(msg);
        parsePaddingLength(msg);
        parseMessageID(msg);
        parseMessageSpecificPayload(msg);
//        parsePayload(msg);
        parsePadding(msg);
        parseMAC(msg);
        return msg;
    }

    public abstract T createMessage();

    protected abstract void parseMessageSpecificPayload(T msg);
    public T parseMessageSpecificPayload(){
        T msg = createMessage();
        parseMessageSpecificPayload(msg);
        return msg;
    }
}
