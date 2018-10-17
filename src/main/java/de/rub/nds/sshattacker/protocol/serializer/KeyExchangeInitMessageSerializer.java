
package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageSerializer extends Serializer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final KeyExchangeInitMessage msg;

    public KeyExchangeInitMessageSerializer(KeyExchangeInitMessage msg) {
        this.msg = msg;
    }
    
    private void serializeCookie(){
        appendBytes(msg.getCookie().getValue());
    }

    private void serializeKeyExchangeAlgorithmsLength(){
        appendInt(msg.getKeyExchangeAlgorithmsLength().getValue(),4);
    }
    
    private void serializeKeyExchangeAlgorithms(){
        appendString(msg.getKeyExchangeAlgorithms().getValue());
    }
    
    private void serializeServerHostKeyAlgorithmsLength(){
        appendInt(msg.getServerHostKeyAlgorithmsLength().getValue(), 4);
    }
    
    private void serializeServerHostKeyAlgorithms(){
        appendString(msg.getServerHostKeyAlgorithms().getValue());
    }
    
    private void serializeEncryptionAlgorithmsClientToServerLength(){
        appendInt(msg.getEncryptionAlgorithmsClientToServerLength().getValue(), 4);
    }
    
    private void serializeEncryptionAlgorithmsClientToServer(){
        appendString(msg.getEncryptionAlgorithmsClientToServer().getValue());
    }
    
    private void serializeEncryptionAlgorithmsServerToClientLength(){
        appendInt(msg.getEncryptionAlgorithmsServerToClientLength().getValue(), 4);
    }
    
    private void serializeEncryptionAlgorithmsServerToClient(){
        appendString(msg.getEncryptionAlgorithmsServerToClient().getValue());
    }
    
    private void serializeMacAlgorithmsClientToServerLength(){
        appendInt(msg.getMacAlgorithmsClientToServerLength().getValue(), 4);
    }

    private void serializeMacAlgorithmsClientToServer(){
        appendString(msg.getMacAlgorithmsClientToServer().getValue());
    }
    
    private void serializeMacAlgorithmsServerToClientLength(){
        appendInt(msg.getMacAlgorithmsServerToClientLength().getValue(), 4);
    }
    
    private void serializeMacAlgorithmsServerToClient(){
        appendString(msg.getMacAlgorithmsServerToClient().getValue());
    }
    
    private void serializeCompressionAlgorithmsClientToServerLength(){
        appendInt(msg.getCompressionAlgorithmsClientToServerLength().getValue(), 4);
    }
    
    private void serializeCompressionAlgorithmsClientToServer(){
        appendString(msg.getCompressionAlgorithmsClientToServer().getValue());
    }
    
    private void serializeCompressionAlgorithmsServerToClientLength(){
        appendInt(msg.getCompressionAlgorithmsServerToClientLength().getValue(), 4);
    }
    
    private void serializeCompressionAlgorithmsServerToClient(){
        appendString(msg.getCompressionAlgorithmsServerToClient().getValue());
    }
    
    private void serializeLanguagesClientToServerLength(){
        appendInt(msg.getLanguagesClientToServerLength().getValue(), 4);
    }
    
    private void serializeLanguagesClientToServer(){
        appendString(msg.getLanguagesClientToServer().getValue());
    }
    
    private void serializeLanguagesServerToClientLength(){
        appendInt(msg.getLanguagesServerToClientLength().getValue(), 4);
    }

    private void serializeLanguagesServerToClient(){
        appendString(msg.getLanguagesServerToClient().getValue());
    }
    
    private void serializeFirstKeyExchangePacketFollows(){
        appendByte(msg.getFirstKeyExchangePacketFollows().getValue());
    }
    
    private void serializeReserved(){
        appendInt(msg.getReserved().getValue(), 4);
    }

    @Override
    protected byte[] serializeBytes() {
        serializeCookie();
        serializeKeyExchangeAlgorithmsLength();
        serializeKeyExchangeAlgorithms();
        serializeServerHostKeyAlgorithmsLength();
        serializeServerHostKeyAlgorithms();
        serializeEncryptionAlgorithmsClientToServerLength();
        serializeEncryptionAlgorithmsClientToServer();
        serializeEncryptionAlgorithmsServerToClientLength();
        serializeEncryptionAlgorithmsServerToClient();
        serializeMacAlgorithmsClientToServerLength();
        serializeMacAlgorithmsClientToServer();
        serializeMacAlgorithmsServerToClientLength();
        serializeMacAlgorithmsServerToClient();
        serializeCompressionAlgorithmsClientToServerLength();
        serializeCompressionAlgorithmsClientToServer();
        serializeCompressionAlgorithmsServerToClientLength();
        serializeCompressionAlgorithmsServerToClient();
        serializeLanguagesClientToServerLength();
        serializeLanguagesClientToServer();
        serializeLanguagesServerToClientLength();
        serializeLanguagesServerToClient();
        serializeFirstKeyExchangePacketFollows();
        serializeReserved();
        return getAlreadySerialized();
    }
}
