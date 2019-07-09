package de.rub.nds.sshattacker.state;

import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MacAlgorithm;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import java.util.List;

public class Chooser {

    private SshContext context;
    private Config config;

    public Chooser(SshContext context) {
        this.context = context;
        config = context.getConfig();
    }

    public String getClientVersion() {
        if (context.getClientVersion() != null) {
            return context.getClientVersion();
        } else {
            return config.getClientVersion();
        }
    }

    public String getClientComment() {
        if (context.getClientComment() != null) {
            return context.getClientComment();
        } else {
            return config.getClientComment();
        }
    }

    public String getServerVersion() {
        if (context.getServerVersion() != null) {
            return context.getServerVersion();
        } else {
            return config.getServerVersion();
        }
    }

    public String getServerComment() {
        if (context.getServerComment() != null) {
            return context.getServerComment();
        } else {
            return config.getServerComment();
        }
    }

    public byte[] getClientCookie() {
        if (context.getClientCookie() != null) {
            return context.getClientCookie();
        } else {
            return config.getClientCookie();
        }
    }

    public byte[] getServerCookie() {
        if (context.getServerCookie() != null) {
            return context.getServerCookie();
        } else {
            return config.getServerCookie();
        }
    }

    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        if (context.getClientSupportedKeyExchangeAlgorithms() != null) {
            return context.getClientSupportedKeyExchangeAlgorithms();
        } else {
            return config.getClientSupportedKeyExchangeAlgorithms();
        }
    }

    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        if (context.getServerSupportedKeyExchangeAlgorithms() != null) {
            return context.getServerSupportedKeyExchangeAlgorithms();
        } else {
            return config.getServerSupportedKeyExchangeAlgorithms();
        }
    }

    public List<PublicKeyAuthenticationAlgorithm> getClientSupportedHostKeyAlgorithms() {
        if (context.getClientSupportedHostKeyAlgorithms() != null) {
            return context.getClientSupportedHostKeyAlgorithms();
        } else {
            return config.getClientSupportedHostKeyAlgorithms();
        }
    }

    public List<PublicKeyAuthenticationAlgorithm> getServerSupportedHostKeyAlgorithms() {
        if (context.getServerSupportedHostKeyAlgorithms() != null) {
            return context.getServerSupportedHostKeyAlgorithms();
        } else {
            return config.getServerSupportedHostKeyAlgorithms();
        }
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsClientToServer() {
        if (context.getClientSupportedCipherAlgorithmsClientToServer() != null) {
            return context.getClientSupportedCipherAlgorithmsClientToServer();
        } else {
            return config.getClientSupportedCipherAlgorithmsClientToServer();
        }
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsServertoClient() {
        if (context.getClientSupportedCipherAlgorithmsServerToClient() != null) {
            return context.getClientSupportedCipherAlgorithmsServerToClient();
        } else {
            return config.getClientSupportedCipherAlgorithmsServerToClient();
        }
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsServerToClient() {
        if (context.getServerSupportedCipherAlgorithmsServerToClient() != null) {
            return context.getServerSupportedCipherAlgorithmsServerToClient();
        } else {
            return config.getServerSupportedCipherAlgorithmsServerToClient();
        }
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsClientToServer() {
        if (context.getServerSupportedCipherAlgorithmsClientToServer() != null) {
            return context.getServerSupportedCipherAlgorithmsClientToServer();
        } else {
            return config.getServerSupportedCipherAlgorithmsClientToServer();
        }
    }

    public List<MacAlgorithm> getClientSupportedMacAlgorithmsClientToServer() {
        if (context.getClientSupportedMacAlgorithmsClientToServer() != null) {
            return context.getClientSupportedMacAlgorithmsClientToServer();
        } else {
            return config.getClientSupportedMacAlgorithmsClientToServer();
        }
    }

    public List<MacAlgorithm> getClientSupportedMacAlgorithmsServerToClient() {
        if (context.getClientSupportedMacAlgorithmsServerToClient() != null) {
            return context.getClientSupportedMacAlgorithmsServerToClient();
        } else {
            return config.getClientSupportedMacAlgorithmsServerToClient();
        }
    }

    public List<MacAlgorithm> getServerSupportedMacAlgorithmsServerToClient() {
        if (context.getServerSupportedMacAlgorithmsServerToClient() != null) {
            return context.getServerSupportedMacAlgorithmsServerToClient();
        } else {
            return config.getServerSupportedMacAlgorithmsServerToClient();
        }
    }

    public List<MacAlgorithm> getServerSupportedMacAlgorithmsClientToServer() {
        if (context.getServerSupportedMacAlgorithmsClientToServer() != null) {
            return context.getServerSupportedMacAlgorithmsClientToServer();
        } else {
            return config.getServerSupportedMacAlgorithmsClientToServer();
        }
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsClientToServer() {
        if (context.getClientSupportedCompressionAlgorithmsClientToServer() != null) {
            return context.getClientSupportedCompressionAlgorithmsClientToServer();
        } else {
            return config.getClientSupportedCompressionAlgorithmsClientToServer();
        }
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsServerToClient() {
        if (context.getClientSupportedCompressionAlgorithmsServerToClient() != null) {
            return context.getClientSupportedCompressionAlgorithmsServerToClient();
        } else {
            return config.getClientSupportedCompressionAlgorithmsServerToClient();
        }
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsServerToClient() {
        if (context.getServerSupportedCompressionAlgorithmsServerToClient() != null) {
            return context.getServerSupportedCompressionAlgorithmsServerToClient();
        } else {
            return config.getServerSupportedCompressionAlgorithmsServerToClient();
        }
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsClientToServer() {
        if (context.getServerSupportedCompressionAlgorithmsClientToServer() != null) {
            return context.getServerSupportedCompressionAlgorithmsClientToServer();
        } else {
            return config.getServerSupportedCompressionAlgorithmsClientToServer();
        }
    }

    public List<Language> getClientSupportedLanguagesClientToServer() {
        if (context.getClientSupportedLanguagesClientToServer() != null) {
            return context.getClientSupportedLanguagesClientToServer();
        } else {
            return config.getClientSupportedLanguagesClientToServer();
        }
    }

    public List<Language> getClientSupportedLanguagesServerToClient() {
        if (context.getClientSupportedLanguagesServerToClient() != null) {
            return context.getClientSupportedLanguagesServerToClient();
        } else {
            return config.getClientSupportedLanguagesServerToClient();
        }
    }

    public List<Language> getServerSupportedLanguagesServerToClient() {
        if (context.getServerSupportedLanguagesServerToClient() != null) {
            return context.getServerSupportedLanguagesServerToClient();
        } else {
            return config.getServerSupportedLanguagesServerToClient();
        }
    }

    public List<Language> getServerSupportedLanguagesClientToServer() {
        if (context.getServerSupportedLanguagesClientToServer() != null) {
            return context.getServerSupportedLanguagesClientToServer();
        } else {
            return config.getServerSupportedLanguagesClientToServer();
        }
    }

    public byte getClientFirstKeyExchangePacketFollows() {
        if (context.getClientFirstKeyExchangePacketFollows() != null) {
            return context.getClientFirstKeyExchangePacketFollows();
        } else {
            return config.getClientFirstKeyExchangePacketFollows();
        }
    }

    public byte getServerFirstKeyExchangePacketFollows() {
        if (context.getServerFirstKeyExchangePacketFollows() != null) {
            return context.getServerFirstKeyExchangePacketFollows();
        } else {
            return config.getServerFirstKeyExchangePacketFollows();
        }
    }

    public int getClientReserved() {
        if (context.getClientReserved() != null) {
            return context.getClientReserved();
        } else {
            return config.getClientReserved();
        }
    }

    public int getServerReserved() {
        if (context.getServerReserved() != null) {
            return context.getServerReserved();
        } else {
            return config.getServerReserved();
        }
    }

    public byte[] getClientEcdhPublicKey() {
        if (context.getClientEcdhPublicKey() != null) {
            return context.getClientEcdhPublicKey();
        } else {
            return config.getClientEcdhPublicKey();
        }
    }

    public byte[] getServerEcdhPublicKey() {
        if (context.getServerEcdhPublicKey() != null) {
            return context.getServerEcdhPublicKey();
        } else {
            return config.getServerEcdhPublicKey();
        }
    }

    public String getUsername() {
        if (context.getUsername() != null) {
            return context.getUsername();
        } else {
            return config.getUsername();
        }
    }

    public String getPassword() {
        if (context.getUsername() != null) {
            return context.getPassword();
        } else {
            return config.getPassword();
        }
    }

    public byte getReplyWanted() {
        return 0;
//        if (context.getReplyWanted() != 0) {
//            return context.getReplyWanted();
//        } else {
//            return config.getReplyWanted();
//        }
    }

    public int getLocalChannel() {
        return 0;
//        if (context.getLocalChannel() != 0) {
//            return context.getLocalChannel();
//        } else {
//            return config.getLocalChannel();
//        }
    }
    
    public String getChannelType() {
        if (context.getChannelType() != null){
            return context.getChannelType();
        } else {
            return config.getChannelType();
        }
    }
    
    public int getWindowSize() {
        if (context.getWindowSize() != 0){
            return context.getWindowSize();
        } else {
            return config.getWindowSize();
        }
    }
    
    public int getPacketSize() {
        if (context.getPacketSize() != 0){
            return context.getPacketSize();
        } else {
            return config.getPacketSize();
        }
    }
    
    public String getChannelRequestType() {
        if (context.getChannelRequestType() != null){
            return context.getChannelRequestType();
        } else {
            return config.getChannelRequestType();
        }
    }
    
    public String getChannelCommand() {
        if (context.getChannelCommand() != null){
            return context.getChannelCommand();
        } else {
            return config.getChannelCommand();
        }
    }
    
    public int getRemoteChannel() {
        return 0;
//        if (context.getRemoteChannel() != 0){
//            return context.getRemoteChannel();
//        } else {
//            return config.getRemoteChannel();
//        }
    }
}
