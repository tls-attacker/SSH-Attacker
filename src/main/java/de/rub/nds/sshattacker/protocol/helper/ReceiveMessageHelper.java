package de.rub.nds.sshattacker.protocol.helper;

import de.rub.nds.sshattacker.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.protocol.parser.ClientInitMessageParser;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public MessageActionResult receiveMessages(SshContext context) {
        TransportHandler transportHandler = context.getTransportHandler();
        BinaryPacketLayer binaryPacketLayer = context.getBinaryPacketLayer();
        MessageLayer messageLayer = context.getMessageLayer();
        CryptoLayer cryptoLayer = context.getCryptoLayer();

        try {
            byte[] data = transportHandler.fetchData();
            if (data.length != 0) {
                List<BinaryPacket> binaryPackets = binaryPacketLayer.parseBinaryPackets(cryptoLayer.decryptBinaryPacket(data));
                List<Message> messages = messageLayer.parseMessages(binaryPackets);
            messages.forEach(message -> {
                message.getHandler(context).handle(message);
            });
            return new MessageActionResult(binaryPackets, messages);
            }
            
            else{
                LOGGER.debug("TransportHandler does not have data.");
                return new MessageActionResult();
            }
        } catch (IOException e) {
            LOGGER.debug("Error while receiving Data " + e.getMessage());
            return new MessageActionResult();
        }
    }
    
    // TODO dummy method until expectedMessages are used
    public MessageActionResult receiveMessages(List<Message> expectedMessages, SshContext context){
        return receiveMessages(context);
    }
    
    public void receiveInitMessage(SshContext context){
        TransportHandler transport = context.getTransportHandler();
        try{
            byte[] response = transport.fetchData();
            ClientInitMessage serverInit = new ClientInitMessageParser(0, response).parse();
             serverInit.getHandler(context).handle(serverInit);
        }
        catch (IOException e){
            LOGGER.debug("Error while receiving ClientInit" + e.getMessage());
        }
    }

}
