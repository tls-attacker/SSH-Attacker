/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.layers;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MessageLayer {

    private static final Logger LOGGER = LogManager.getLogger();
    private final SshContext context;

    public MessageLayer(SshContext context) {
        this.context = context;
    }

    public List<Message<?>> parseMessages(List<BinaryPacket> list) {
        List<Message<?>> returnList = new ArrayList<>();
        for (BinaryPacket packet : list) {
            Message<?> msg = MessageParser.delegateParsing(packet.getPayload().getValue(), context);
          //  LOGGER.debug("Message Content: " + ArrayConverter.bytesToHexString(msg.getCompleteResultingMessage().getValue()));
            returnList.add(msg);
        }
        return returnList;
    }

    public BinaryPacket serializeMessage(Message<?> msg) {
        BinaryPacket packet = new BinaryPacket();
        byte[] payload = MessageSerializer.delegateSerialization(msg);
        packet.setPayload(payload);
        // Compute with minimal block length (assuming no encryption later on)
        // If the package will be encrypted, padding will be recalculated in CryptoLayer (necessary
        // for ETM support)
        packet.computePaddingLength((byte) 8);
        packet.generatePadding();
        packet.computePacketLength();
        return packet;
    }

    public List<BinaryPacket> serializeMessages(List<Message<?>> list) {
        List<BinaryPacket> returnList = new ArrayList<>();
        for (Message<?> msg : list) {
            BinaryPacket packet = serializeMessage(msg);
            returnList.add(packet);
        }
        return returnList;
    }
}
