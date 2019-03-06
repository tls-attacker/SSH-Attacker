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

public class ReceiveMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public void receiveMessages(SshContext context) {
        TransportHandler transportHandler = context.getTransportHandler();
        BinaryPacketLayer binaryPacketLayer = context.getBinaryPacketLayer();
        MessageLayer messageLayer = context.getMessageLayer();

        try {
            List<Message> messages = messageLayer.parseMessages(binaryPacketLayer.parseBinaryPackets(transportHandler.fetchData()));
            messages.forEach(message -> {
                message.getHandler(context).handle(message);
            });
        } catch (IOException e) {
            LOGGER.debug("Error while receiving Data " + e.getMessage());
        }
    }

}
