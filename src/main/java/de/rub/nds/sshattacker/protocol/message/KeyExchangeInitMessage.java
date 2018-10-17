
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Message;

public class KeyExchangeInitMessage extends Message {

    private ModifiableByteArray cookie;
    private ModifiableInteger keyExchangeAlgorithmsLength;
    private ModifiableString keyExchangeAlgorithms;
    private ModifiableInteger serverHostKeyAlgorithmsLength;
    private ModifiableString serverHostKeyAlgorithms;
    private ModifiableInteger encryptionAlgorithmsClientToServerLength;
    private ModifiableString encryptionAlgorithmsClientToServer;
    private ModifiableInteger encryptionAlgorithmsServerToClientLength;
    private ModifiableString encryptionAlgorithmsServerToClient;
    private ModifiableInteger macAlgorithmsClientToServerLength;
    private ModifiableString macAlgorithmsClientToServer;
    private ModifiableInteger macAlgorithmsServerToClientLength;
    private ModifiableString macAlgorithmsServerToClient;
    private ModifiableInteger compressionAlgorithmsClientToServerLength;
    private ModifiableString compressionAlgorithmsClientToServer;
    private ModifiableInteger compressionAlgorithmsServerToClientLength;
    private ModifiableString compressionAlgorithmsServerToClient;
    private ModifiableInteger languagesClientToServerLength;
    private ModifiableString languagesClientToServer;
    private ModifiableInteger languagesServerToClientLength;
    private ModifiableString languagesServerToClient;
    private ModifiableByte firstKeyExchangePacketFollows;
    private ModifiableInteger reserved;

    public ModifiableInteger getKeyExchangeAlgorithmsLength() {
        return keyExchangeAlgorithmsLength;
    }

    public void setKeyExchangeAlgorithmsLength(ModifiableInteger keyExchangeAlgorithmsLength) {
        this.keyExchangeAlgorithmsLength = keyExchangeAlgorithmsLength;
    }
    
    public void setKeyExchangeAlgorithmsLength(int keyExchangeAlgorithmsLength) {
        this.keyExchangeAlgorithmsLength = ModifiableVariableFactory.safelySetValue(this.keyExchangeAlgorithmsLength, keyExchangeAlgorithmsLength);
    }

    public ModifiableInteger getServerHostKeyAlgorithmsLength() {
        return serverHostKeyAlgorithmsLength;
    }

    public void setServerHostKeyAlgorithmsLength(ModifiableInteger serverHostKeyAlgorithmsLength) {
        this.serverHostKeyAlgorithmsLength = serverHostKeyAlgorithmsLength;
    }
    
    public void setServerHostKeyAlgorithmsLength(int serverHostKeyAlgorithmsLength) {
        this.serverHostKeyAlgorithmsLength = ModifiableVariableFactory.safelySetValue(this.serverHostKeyAlgorithmsLength,serverHostKeyAlgorithmsLength);
    }

    public ModifiableInteger getEncryptionAlgorithmsClientToServerLength() {
        return encryptionAlgorithmsClientToServerLength;
    }

    public void setEncryptionAlgorithmsClientToServerLength(ModifiableInteger encryptionAlgorithmsClientToServerLength) {
        this.encryptionAlgorithmsClientToServerLength = encryptionAlgorithmsClientToServerLength;
    }
    
    public void setEncryptionAlgorithmsClientToServerLength(int encryptionAlgorithmsClientToServerLength) {
        this.encryptionAlgorithmsClientToServerLength = ModifiableVariableFactory.safelySetValue(this.encryptionAlgorithmsClientToServerLength,encryptionAlgorithmsClientToServerLength);
    }

    public ModifiableInteger getEncryptionAlgorithmsServerToClientLength() {
        return encryptionAlgorithmsServerToClientLength;
    }

    public void setEncryptionAlgorithmsServerToClientLength(ModifiableInteger encryptionAlgorithmsServerToClientLength) {
        this.encryptionAlgorithmsServerToClientLength = encryptionAlgorithmsServerToClientLength;
    }
    
    public void setEncryptionAlgorithmsServerToClientLength(int encryptionAlgorithmsServerToClientLength) {
        this.encryptionAlgorithmsServerToClientLength = ModifiableVariableFactory.safelySetValue(this.encryptionAlgorithmsServerToClientLength, encryptionAlgorithmsServerToClientLength);
    }

    public ModifiableInteger getMacAlgorithmsClientToServerLength() {
        return macAlgorithmsClientToServerLength;
    }

    public void setMacAlgorithmsClientToServerLength(ModifiableInteger macAlgorithmsClientToServerLength) {
        this.macAlgorithmsClientToServerLength = macAlgorithmsClientToServerLength;
    }
    
    public void setMacAlgorithmsClientToServerLength(int macAlgorithmsClientToServerLength) {
        this.macAlgorithmsClientToServerLength = ModifiableVariableFactory.safelySetValue(this.macAlgorithmsClientToServerLength, macAlgorithmsClientToServerLength);
    }

    public ModifiableInteger getMacAlgorithmsServerToClientLength() {
        return macAlgorithmsServerToClientLength;
    }

    public void setMacAlgorithmsServerToClientLength(ModifiableInteger macAlgorithmsServerToClientLength) {
        this.macAlgorithmsServerToClientLength = macAlgorithmsServerToClientLength;
    }
    
    public void setMacAlgorithmsServerToClientLength(int macAlgorithmsServerToClientLength) {
        this.macAlgorithmsServerToClientLength = ModifiableVariableFactory.safelySetValue(this.macAlgorithmsServerToClientLength, macAlgorithmsServerToClientLength);
    }

    public ModifiableInteger getCompressionAlgorithmsClientToServerLength() {
        return compressionAlgorithmsClientToServerLength;
    }

    public void setCompressionAlgorithmsClientToServerLength(ModifiableInteger compressionAlgorithmsClientToServerLength) {
        this.compressionAlgorithmsClientToServerLength = compressionAlgorithmsClientToServerLength;
    }
    
    public void setCompressionAlgorithmsClientToServerLength(int compressionAlgorithmsClientToServerLength) {
        this.compressionAlgorithmsClientToServerLength = ModifiableVariableFactory.safelySetValue(this.compressionAlgorithmsClientToServerLength, compressionAlgorithmsClientToServerLength);
    }

    public ModifiableInteger getCompressionAlgorithmsServerToClientLength() {
        return compressionAlgorithmsServerToClientLength;
    }

    public void setCompressionAlgorithmsServerToClientLength(ModifiableInteger compressionAlgorithmsServerToClientLength) {
        this.compressionAlgorithmsServerToClientLength = compressionAlgorithmsServerToClientLength;
    }
    
    public void setCompressionAlgorithmsServerToClientLength(int compressionAlgorithmsServerToClientLength) {
        this.compressionAlgorithmsServerToClientLength = ModifiableVariableFactory.safelySetValue(this.compressionAlgorithmsServerToClientLength, compressionAlgorithmsServerToClientLength);
    }

    public ModifiableInteger getLanguagesClientToServerLength() {
        return languagesClientToServerLength;
    }

    public void setLanguagesClientToServerLength(ModifiableInteger languagesClientToServerLength) {
        this.languagesClientToServerLength = languagesClientToServerLength;
    }
    
    public void setLanguagesClientToServerLength(int languagesClientToServerLength) {
        this.languagesClientToServerLength = ModifiableVariableFactory.safelySetValue(this.languagesClientToServerLength, languagesClientToServerLength);
    }

    public ModifiableInteger getLanguagesServerToClientLength() {
        return languagesServerToClientLength;
    }

    public void setLanguagesServerToClientLength(ModifiableInteger languagesServerToClientLength) {
        this.languagesServerToClientLength = languagesServerToClientLength;
    }
    
    public void setLanguagesServerToClientLength(int languagesServerToClientLength) {
        this.languagesServerToClientLength = ModifiableVariableFactory.safelySetValue(this.languagesServerToClientLength, languagesServerToClientLength);
    }

    public ModifiableByteArray getCookie() {
        return cookie;
    }

    public void setCookie(ModifiableByteArray cookie) {
        this.cookie = cookie;
    }
    
    public void setCookie(byte[] cookie) {
        this.cookie = ModifiableVariableFactory.safelySetValue(this.cookie, cookie);
    }

    public ModifiableString getKeyExchangeAlgorithms() {
        return keyExchangeAlgorithms;
    }

    public void setKeyExchangeAlgorithms(ModifiableString keyExchangeAlgorithms) {
        this.keyExchangeAlgorithms = keyExchangeAlgorithms;
    }
    
    public void setKeyExchangeAlgorithms(String keyExchangeAlgorithms) {
        this.keyExchangeAlgorithms = ModifiableVariableFactory.safelySetValue(this.keyExchangeAlgorithms, keyExchangeAlgorithms);
    }

    public ModifiableString getServerHostKeyAlgorithms() {
        return serverHostKeyAlgorithms;
    }

    public void setServerHostKeyAlgorithms(ModifiableString serverHostKeyAlgorithms) {
        this.serverHostKeyAlgorithms = serverHostKeyAlgorithms;
    }
    
    public void setServerHostKeyAlgorithms(String serverHostKeyAlgorithms) {
        this.serverHostKeyAlgorithms = ModifiableVariableFactory.safelySetValue(this.serverHostKeyAlgorithms, serverHostKeyAlgorithms);
    }

    public ModifiableString getEncryptionAlgorithmsClientToServer() {
        return encryptionAlgorithmsClientToServer;
    }

    public void setEncryptionAlgorithmsClientToServer(ModifiableString encryptionAlgorithmsClientToServer) {
        this.encryptionAlgorithmsClientToServer = encryptionAlgorithmsClientToServer;
    }
    
    public void setEncryptionAlgorithmsClientToServer(String encryptionAlgorithmsClientToServer) {
        this.encryptionAlgorithmsClientToServer = ModifiableVariableFactory.safelySetValue(this.encryptionAlgorithmsClientToServer, encryptionAlgorithmsClientToServer);
    }

    public ModifiableString getEncryptionAlgorithmsServerToClient() {
        return encryptionAlgorithmsServerToClient;
    }

    public void setEncryptionAlgorithmsServerToClient(ModifiableString encryptionAlgorithmsServerToClient) {
        this.encryptionAlgorithmsServerToClient = encryptionAlgorithmsServerToClient;
    }
    
    public void setEncryptionAlgorithmsServerToClient(String encryptionAlgorithmsServerToClient) {
        this.encryptionAlgorithmsServerToClient = ModifiableVariableFactory.safelySetValue(this.encryptionAlgorithmsServerToClient, encryptionAlgorithmsServerToClient);
    }

    public ModifiableString getMacAlgorithmsClientToServer() {
        return macAlgorithmsClientToServer;
    }

    public void setMacAlgorithmsClientToServer(ModifiableString macAlgorithmsClientToServer) {
        this.macAlgorithmsClientToServer = macAlgorithmsClientToServer;
    }
    
    public void setMacAlgorithmsClientToServer(String macAlgorithmsClientToServer) {
        this.macAlgorithmsClientToServer = ModifiableVariableFactory.safelySetValue(this.macAlgorithmsClientToServer, macAlgorithmsClientToServer);
    }

    public ModifiableString getMacAlgorithmsServerToClient() {
        return macAlgorithmsServerToClient;
    }

    public void setMacAlgorithmsServerToClient(ModifiableString macAlgorithmsServerToClient) {
        this.macAlgorithmsServerToClient = macAlgorithmsServerToClient;
    }
    
    public void setMacAlgorithmsServerToClient(String macAlgorithmsServerToClient) {
        this.macAlgorithmsServerToClient = ModifiableVariableFactory.safelySetValue(this.macAlgorithmsServerToClient, macAlgorithmsServerToClient);
    }

    public ModifiableString getCompressionAlgorithmsClientToServer() {
        return compressionAlgorithmsClientToServer;
    }

    public void setCompressionAlgorithmsClientToServer(ModifiableString compressionAlgorithmsClientToServer) {
        this.compressionAlgorithmsClientToServer = compressionAlgorithmsClientToServer;
    }
    
    public void setCompressionAlgorithmsClientToServer(String compressionAlgorithmsClientToServer) {
        this.compressionAlgorithmsClientToServer = ModifiableVariableFactory.safelySetValue(this.compressionAlgorithmsClientToServer, compressionAlgorithmsClientToServer);
    }

    public ModifiableString getCompressionAlgorithmsServerToClient() {
        return compressionAlgorithmsServerToClient;
    }

    public void setCompressionAlgorithmsServerToClient(ModifiableString compressionAlgorithmsServerToClient) {
        this.compressionAlgorithmsServerToClient = compressionAlgorithmsServerToClient;
    }
    
    public void setCompressionAlgorithmsServerToClient(String compressionAlgorithmsServerToClient) {
        this.compressionAlgorithmsServerToClient = ModifiableVariableFactory.safelySetValue(this.compressionAlgorithmsServerToClient, compressionAlgorithmsServerToClient);
    }

    public ModifiableString getLanguagesClientToServer() {
        return languagesClientToServer;
    }

    public void setLanguagesClientToServer(ModifiableString languagesClientToServer) {
        this.languagesClientToServer = languagesClientToServer;
    }
    
    public void setLanguagesClientToServer(String languagesClientToServer) {
        this.languagesClientToServer = ModifiableVariableFactory.safelySetValue(this.languagesClientToServer, languagesClientToServer);
    }

    public ModifiableString getLanguagesServerToClient() {
        return languagesServerToClient;
    }

    public void setLanguagesServerToClient(ModifiableString languagesServerToClient) {
        this.languagesServerToClient = languagesServerToClient;
    }
    
    public void setLanguagesServerToClient(String languagesServerToClient) {
        this.languagesServerToClient = ModifiableVariableFactory.safelySetValue(this.languagesServerToClient, languagesServerToClient);
    }

    public ModifiableByte getFirstKeyExchangePacketFollows() {
        return firstKeyExchangePacketFollows;
    }

    public void setFirstKeyExchangePacketFollows(ModifiableByte firstKeyExchangePacketFollows) {
        this.firstKeyExchangePacketFollows = firstKeyExchangePacketFollows;
    }
    
    public void setFirstKeyExchangePacketFollows(byte firstKeyExchangePacketFollows) {
        this.firstKeyExchangePacketFollows = ModifiableVariableFactory.safelySetValue(this.firstKeyExchangePacketFollows, firstKeyExchangePacketFollows);
    }

    public ModifiableInteger getReserved() {
        return reserved;
    }

    public void setReserved(ModifiableInteger reserved) {
        this.reserved = reserved;
    }
    
    public void setReserved(int reserved) {
        this.reserved = ModifiableVariableFactory.safelySetValue(this.reserved, reserved);
    }
    
    @Override
    public String toCompactString() {
        return "KeyExchangeInitMessage";
    }

}
