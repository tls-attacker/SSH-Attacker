
package de.rub.nds.sshattacker.protocol.parser;

import de.rub.nds.protocol.core.message.Parser;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExchangeInitMessageParser extends Parser<KeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public KeyExchangeInitMessageParser(int startPosition, byte[] array){
        super(startPosition, array);
    }
    
    private void parseCookie(KeyExchangeInitMessage msg){
        msg.setCookie(parseByteArrayField(16));
        LOGGER.debug("Cookie: " + msg.getCookie());
    }
    
    private void parseKeyExchangeAlgorithmsLength(KeyExchangeInitMessage msg){
        msg.setKeyExchangeAlgorithmsLength(parseIntField(4));
        LOGGER.debug("KeyExchangeAlgorithmsLength: " + msg.getKeyExchangeAlgorithmsLength().getValue());
    }
    
    private void parseKeyExchangeAlgorithms(KeyExchangeInitMessage msg){
        msg.setKeyExchangeAlgorithms(parseByteString(msg.getKeyExchangeAlgorithmsLength().getValue()));
        LOGGER.debug("KeyExchangeAlgorithms: " + msg.getKeyExchangeAlgorithms().getValue());
    }
    
    private void parseServerHostKeyAlgorithmsLength(KeyExchangeInitMessage msg){
        msg.setServerHostKeyAlgorithmsLength(parseIntField(4));
        LOGGER.debug("ServerHostKeyAlgorithmsLength: " + msg.getServerHostKeyAlgorithmsLength().getValue());
    }
    
    private void parseServerHostKeyAlgorithms(KeyExchangeInitMessage msg){
        msg.setServerHostKeyAlgorithms(parseByteString(msg.getServerHostKeyAlgorithmsLength().getValue()));
        LOGGER.debug("ServerHostKeyAlgorithms: " + msg.getServerHostKeyAlgorithms().getValue());
    }
    
    private void parseEncryptionAlgorithmsClientToServerLength(KeyExchangeInitMessage msg){
        msg.setEncryptionAlgorithmsClientToServerLength(parseIntField(4));
        LOGGER.debug("EncryptionAlgorithmsClientToServerLength: " + msg.getEncryptionAlgorithmsClientToServerLength().getValue());
    }
    
    private void parseEncryptionAlgorithmsClientToServer(KeyExchangeInitMessage msg){
        msg.setEncryptionAlgorithmsClientToServer(parseByteString(msg.getEncryptionAlgorithmsClientToServerLength().getValue()));
        LOGGER.debug("EncryptionAlgorithmsClientToServer: " + msg.getEncryptionAlgorithmsClientToServer().getValue());
    }
    
    private void parseEncryptionAlgorithmsServerToClientLength(KeyExchangeInitMessage msg){
        msg.setEncryptionAlgorithmsServerToClientLength(parseIntField(4));
        LOGGER.debug("EncryptionAlgorithmsServerToClientLength: " + msg.getEncryptionAlgorithmsServerToClientLength().getValue());
    }
    
    private void parseEncryptionAlgorithmsServerToClient(KeyExchangeInitMessage msg){
        msg.setEncryptionAlgorithmsServerToClient(parseByteString(msg.getEncryptionAlgorithmsServerToClientLength().getValue()));
        LOGGER.debug("EncryptionAlgorithmsServerToClient: " + msg.getEncryptionAlgorithmsServerToClient().getValue());
    }
    
    private void parseMacAlgorithmsClientToServerLength(KeyExchangeInitMessage msg){
        msg.setMacAlgorithmsClientToServerLength(parseIntField(4));
        LOGGER.debug("MacAlgorithmsClientToServerLength: " + msg.getMacAlgorithmsClientToServerLength().getValue());
    }
    
    private void parseMacAlgorithmsClientToServer(KeyExchangeInitMessage msg){
        msg.setMacAlgorithmsClientToServer(parseByteString(msg.getMacAlgorithmsClientToServerLength().getValue()));
        LOGGER.debug("MacAlgorithmsClientToServer: " + msg.getMacAlgorithmsClientToServer().getValue());
    }
    
    private void parseMacAlgorithmsServerToClientLength(KeyExchangeInitMessage msg){
        msg.setMacAlgorithmsServerToClientLength(parseIntField(4));
        LOGGER.debug("MacAlgorithmsServerToClientLength: " + msg.getMacAlgorithmsServerToClientLength().getValue());
    }
    
    private void parseMacAlgorithmsServerToClient(KeyExchangeInitMessage msg){
        msg.setMacAlgorithmsServerToClient(parseByteString(msg.getMacAlgorithmsServerToClientLength().getValue()));
        LOGGER.debug("MacAlgorithmsServerToClient: " + msg.getMacAlgorithmsServerToClient().getValue());
    }
    
    private void parseCompressionAlgorithmsClientToServerLength(KeyExchangeInitMessage msg){
        msg.setCompressionAlgorithmsClientToServerLength(parseIntField(4));
        LOGGER.debug("CompressionAlgorithmsClientToServerLength: " + msg.getCompressionAlgorithmsClientToServerLength().getValue());
    }
    
    private void parseCompressionAlgorithmsClientToServer(KeyExchangeInitMessage msg){
        msg.setCompressionAlgorithmsClientToServer(parseByteString(msg.getCompressionAlgorithmsClientToServerLength().getValue()));
        LOGGER.debug("CompressionAlgorithmsClientToServer: " + msg.getCompressionAlgorithmsClientToServer().getValue());
    }
    
    private void parseCompressionAlgorithmsServerToClientLength(KeyExchangeInitMessage msg){
        msg.setCompressionAlgorithmsServerToClientLength(parseIntField(4));
        LOGGER.debug("CompressionAlgorithmsServerToClientLength: " + msg.getCompressionAlgorithmsServerToClientLength().getValue());
    }
    
    private void parseCompressionAlgorithmsServerToClient(KeyExchangeInitMessage msg){
        msg.setCompressionAlgorithmsServerToClient(parseByteString(msg.getCompressionAlgorithmsServerToClientLength().getValue()));
        LOGGER.debug("CompressionAlgorithmsServerToClient" + msg.getCompressionAlgorithmsServerToClient().getValue());
    }
    
    private void parseLanguagesClientToServerLength(KeyExchangeInitMessage msg){
        msg.setLanguagesClientToServerLength(parseIntField(4));
        LOGGER.debug("LanguagesClientToServerLength: " + msg.getLanguagesClientToServerLength().getValue());
    }
    
    private void parseLanguagesClientToServer(KeyExchangeInitMessage msg){
        msg.setLanguagesClientToServer(parseByteString(msg.getLanguagesClientToServerLength().getValue()));
        LOGGER.debug("LanguagesClientToServer: " + msg.getLanguagesClientToServer().getValue());
    }
    
    private void parseLanguagesServerToClientLength(KeyExchangeInitMessage msg){
        msg.setLanguagesServerToClientLength(parseIntField(4));
        LOGGER.debug("LanguagesServerToClientLength: " + msg.getLanguagesServerToClientLength().getValue());
    }
    
    private void parseLanguagesServerToClient(KeyExchangeInitMessage msg){
        msg.setLanguagesServerToClient(parseByteString(msg.getLanguagesServerToClientLength().getValue()));
        LOGGER.debug("LanguagesServerToClient: " + msg.getLanguagesServerToClient().getValue());
    }
    
    private void parseFirstKeyExchangePacketFollows(KeyExchangeInitMessage msg){
        msg.setFirstKeyExchangePacketFollows(parseByteField(1));
        LOGGER.debug("FirstKeyExchangePacketFollows: " + msg.getFirstKeyExchangePacketFollows().getValue());
    }
    
    private void parseReserved(KeyExchangeInitMessage msg){
        msg.setReserved(parseIntField(4));
        LOGGER.debug("Reserved: " + msg.getReserved().getValue());
    }
    
    @Override
    public KeyExchangeInitMessage parse() {
        KeyExchangeInitMessage msg = new KeyExchangeInitMessage();
        parseCookie(msg);
        parseKeyExchangeAlgorithmsLength(msg);
        parseKeyExchangeAlgorithms(msg);
        parseServerHostKeyAlgorithmsLength(msg);
        parseServerHostKeyAlgorithms(msg);
        parseEncryptionAlgorithmsClientToServerLength(msg);
        parseEncryptionAlgorithmsClientToServer(msg);
        parseEncryptionAlgorithmsServerToClientLength(msg);
        parseEncryptionAlgorithmsServerToClient(msg);
        parseMacAlgorithmsClientToServerLength(msg);
        parseMacAlgorithmsClientToServer(msg);
        parseMacAlgorithmsServerToClientLength(msg);
        parseMacAlgorithmsServerToClient(msg);
        parseCompressionAlgorithmsClientToServerLength(msg);
        parseCompressionAlgorithmsClientToServer(msg);
        parseCompressionAlgorithmsServerToClientLength(msg);
        parseCompressionAlgorithmsServerToClient(msg);
        parseLanguagesClientToServerLength(msg);
        parseLanguagesClientToServer(msg);
        parseLanguagesServerToClientLength(msg);
        parseLanguagesServerToClient(msg);
        parseFirstKeyExchangePacketFollows(msg);
        parseReserved(msg);
        return msg;
    }
}
