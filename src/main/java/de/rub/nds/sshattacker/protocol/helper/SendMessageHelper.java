package de.rub.nds.sshattacker.protocol.helper;

import de.rub.nds.sshattacker.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.workflow.action.MessageAction;
import de.rub.nds.sshattacker.workflow.action.result.MessageActionResult;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();
    
    public MessageActionResult sendMessage(Message msg, SshContext context){
        MessageLayer messageLayer = context.getMessageLayer();
        BinaryPacketLayer binaryPacketLayer = context.getBinaryPacketLayer();
        TransportHandler transportHandler = context.getTransportHandler();
        CryptoLayer cryptoLayer = context.getCryptoLayer();
        
        try{
            BinaryPacket binaryPacket = messageLayer.serializeMessage(msg);
            transportHandler.sendData(cryptoLayer.macAndEncrypt(binaryPacketLayer.serializeBinaryPacket(binaryPacket)));
            context.incrementSequenceNumber();
            return new MessageActionResult(Arrays.asList(binaryPacket), Arrays.asList(msg));
        }
        catch (IOException e)
        {
            LOGGER.warn("Error while sending packet: " + e.getMessage());
            return new MessageActionResult();
        }
    }
    
    public MessageActionResult sendMessages(List<Message> list, SshContext context) {
        MessageActionResult result = new MessageActionResult();
        for(Message msg : list){
            result.merge(sendMessage(msg, context));
        }
        return result;
    }
    
    // TODO dummy
    public MessageActionResult sendMessages(List<Message> messageList, List<BinaryPacket> binaryPackets, SshContext context) {
        return sendMessages(messageList, context);
    }
    
    public void sendInitMessage(ClientInitMessage msg, SshContext context){
        TransportHandler transport = context.getTransportHandler();
        try{
            transport.sendData(msg.getSerializer().serialize());
        }
        catch (IOException e){
            LOGGER.debug("Error while sending ClientInitMessage" + e.getMessage());
        }
    }
}
