package de.rub.nds.sshattacker.protocol.helper;

import de.rub.nds.sshattacker.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.Message;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public void sendMessage(Message msg, SshContext context){
        MessageLayer messageLayer = context.getMessageLayer();
        BinaryPacketLayer binaryPacketLayer = context.getBinaryPacketLayer();
        TransportHandler transportHandler = context.getTransportHandler();
        CryptoLayer cryptoLayer = context.getCryptoLayer();
        
        try{
            transportHandler.sendData(cryptoLayer.macAndEncrypt(binaryPacketLayer.serializeBinaryPacket(messageLayer.serializeMessage(msg))));
            context.incrementSequenceNumber();
        }
        catch (IOException e)
        {
            LOGGER.warn("Error while sending packet: " + e.getMessage());
        }
    }
    public void sendMessages(List<Message> list, SshContext context) {
        for(Message msg : list){
            sendMessage(msg, context);
        }
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
