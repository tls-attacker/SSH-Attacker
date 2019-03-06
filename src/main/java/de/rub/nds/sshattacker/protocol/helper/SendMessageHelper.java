package de.rub.nds.sshattacker.protocol.helper;

import de.rub.nds.sshattacker.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public void sendMessages(List<Message> list, SshContext context) {
        MessageLayer messageLayer = context.getMessageLayer();
        BinaryPacketLayer binaryPacketLayer = context.getBinaryPacketLayer();
        TransportHandler transport = context.getTransportHandler();

        try {
            transport.sendData(binaryPacketLayer.serializeBinaryPackets(messageLayer.serializeMessages(list)));
        } catch (IOException e) {
            LOGGER.debug("Error while sending messages" + e.getMessage());
        }
    }
}
