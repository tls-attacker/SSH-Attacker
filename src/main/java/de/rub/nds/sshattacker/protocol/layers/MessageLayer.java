package de.rub.nds.sshattacker.protocol.layers;

import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.protocol.parser.MessageParser;
import de.rub.nds.sshattacker.protocol.serializer.MessageSerializer;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MessageLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    public List<Message> parseMessages(List<BinaryPacket> list) {
        List<Message> returnList = new ArrayList<>();
        for (BinaryPacket packet : list) {
            Message msg = MessageParser.delegateParsing(packet.getPayload().getValue());
            returnList.add(msg);
        }
        return returnList;
    }

    public List<BinaryPacket> serializeMessages(List<Message> list) {
        List<BinaryPacket> returnList = new ArrayList();
        for (Message msg : list) {
            BinaryPacket packet = new BinaryPacket();
            byte[] payload = MessageSerializer.delegateSerialization(msg);
            packet.setPayload(payload);
            packet.computePaddingLength((byte) 8);
            packet.generatePadding();
            packet.computePacketLength();
            returnList.add(packet);
        }
        return returnList;
    }
}
