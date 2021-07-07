/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.state;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.*;

import java.util.List;

public class Chooser {

    private final SshContext context;
    private final Config config;

    public Chooser(SshContext context) {
        this.context = context;
        config = context.getConfig();
    }

    public String getClientVersion() {
        return context.getClientVersion().orElse(config.getClientVersion());
    }

    public String getClientComment() {
        return context.getClientComment().orElse(config.getClientComment());
    }

    public String getServerVersion() {
        return context.getServerVersion().orElse(config.getServerVersion());
    }

    public String getServerComment() {
        return context.getServerComment().orElse(config.getServerComment());
    }

    public byte[] getClientCookie() {
        return context.getClientCookie().orElse(config.getClientCookie());
    }

    public byte[] getServerCookie() {
        return context.getServerCookie().orElse(config.getServerCookie());
    }

    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        return context.getClientSupportedKeyExchangeAlgorithms().orElse(
                config.getClientSupportedKeyExchangeAlgorithms());
    }

    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        return context.getServerSupportedKeyExchangeAlgorithms().orElse(
                config.getServerSupportedKeyExchangeAlgorithms());
    }

    public List<PublicKeyAuthenticationAlgorithm> getClientSupportedHostKeyAlgorithms() {
        return context.getClientSupportedHostKeyAlgorithms().orElse(config.getClientSupportedHostKeyAlgorithms());
    }

    public List<PublicKeyAuthenticationAlgorithm> getServerSupportedHostKeyAlgorithms() {
        return context.getServerSupportedHostKeyAlgorithms().orElse(config.getServerSupportedHostKeyAlgorithms());
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsClientToServer() {
        return context.getClientSupportedCipherAlgorithmsClientToServer().orElse(
                config.getClientSupportedCipherAlgorithmsClientToServer());
    }

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsServertoClient() {
        return context.getClientSupportedCipherAlgorithmsServertoClient().orElse(
                config.getClientSupportedCipherAlgorithmsServerToClient());
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsServerToClient() {
        return context.getServerSupportedCipherAlgorithmsServerToClient().orElse(
                config.getServerSupportedCipherAlgorithmsServerToClient());
    }

    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsClientToServer() {
        return context.getServerSupportedCipherAlgorithmsClientToServer().orElse(
                config.getServerSupportedCipherAlgorithmsClientToServer());
    }

    public List<MacAlgorithm> getClientSupportedMacAlgorithmsClientToServer() {
        return context.getClientSupportedMacAlgorithmsClientToServer().orElse(
                config.getClientSupportedMacAlgorithmsClientToServer());
    }

    public List<MacAlgorithm> getClientSupportedMacAlgorithmsServerToClient() {
        return context.getClientSupportedMacAlgorithmsServerToClient().orElse(
                config.getClientSupportedMacAlgorithmsServerToClient());
    }

    public List<MacAlgorithm> getServerSupportedMacAlgorithmsServerToClient() {
        return context.getServerSupportedMacAlgorithmsServerToClient().orElse(
                config.getServerSupportedMacAlgorithmsServerToClient());
    }

    public List<MacAlgorithm> getServerSupportedMacAlgorithmsClientToServer() {
        return context.getServerSupportedMacAlgorithmsClientToServer().orElse(
                config.getServerSupportedMacAlgorithmsClientToServer());
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsClientToServer() {
        return context.getClientSupportedCompressionAlgorithmsClientToServer().orElse(
                config.getClientSupportedCompressionAlgorithmsClientToServer());
    }

    public List<CompressionAlgorithm> getClientSupportedCompressionAlgorithmsServerToClient() {
        return context.getClientSupportedCompressionAlgorithmsServerToClient().orElse(
                config.getClientSupportedCompressionAlgorithmsServerToClient());
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsServerToClient() {
        return context.getServerSupportedCompressionAlgorithmsServerToClient().orElse(
                config.getServerSupportedCompressionAlgorithmsServerToClient());
    }

    public List<CompressionAlgorithm> getServerSupportedCompressionAlgorithmsClientToServer() {
        return context.getServerSupportedCompressionAlgorithmsClientToServer().orElse(
                config.getServerSupportedCompressionAlgorithmsClientToServer());
    }

    public List<Language> getClientSupportedLanguagesClientToServer() {
        return context.getClientSupportedLanguagesClientToServer().orElse(
                config.getClientSupportedLanguagesClientToServer());
    }

    public List<Language> getClientSupportedLanguagesServerToClient() {
        return context.getClientSupportedLanguagesServerToClient().orElse(
                config.getClientSupportedLanguagesServerToClient());
    }

    public List<Language> getServerSupportedLanguagesServerToClient() {
        return context.getServerSupportedLanguagesServerToClient().orElse(
                config.getServerSupportedLanguagesServerToClient());
    }

    public List<Language> getServerSupportedLanguagesClientToServer() {
        return context.getServerSupportedLanguagesClientToServer().orElse(
                config.getServerSupportedLanguagesClientToServer());
    }

    public byte getClientFirstKeyExchangePacketFollows() {
        return context.getClientFirstKeyExchangePacketFollows().orElse(config.getClientFirstKeyExchangePacketFollows());
    }

    public byte getServerFirstKeyExchangePacketFollows() {
        return context.getServerFirstKeyExchangePacketFollows().orElse(config.getServerFirstKeyExchangePacketFollows());
    }

    public int getClientReserved() {
        return context.getClientReserved().orElse(config.getClientReserved());
    }

    public int getServerReserved() {
        return context.getServerReserved().orElse(config.getServerReserved());
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

    public AuthenticationMethod getAuthenticationMethod() {
        return context.getAuthenticationMethod().orElse(config.getAuthenticationMethod());
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
        // if (context.getReplyWanted() != 0) {
        // return context.getReplyWanted();
        // } else {
        // return config.getReplyWanted();
        // }
    }

    public int getLocalChannel() {
        return 0;
        // if (context.getLocalChannel() != 0) {
        // return context.getLocalChannel();
        // } else {
        // return config.getLocalChannel();
        // }
    }

    public ChannelType getChannelType() {
        if (context.getChannelType() != null) {
            return context.getChannelType();
        } else {
            return config.getChannelType();
        }
    }

    public int getWindowSize() {
        if (context.getWindowSize() != 0) {
            return context.getWindowSize();
        } else {
            return config.getWindowSize();
        }
    }

    public int getPacketSize() {
        if (context.getPacketSize() != 0) {
            return context.getPacketSize();
        } else {
            return config.getPacketSize();
        }
    }

    public ChannelRequestType getChannelRequestType() {
        if (context.getChannelRequestType() != null) {
            return context.getChannelRequestType();
        } else {
            return config.getChannelRequestType();
        }
    }

    public String getChannelCommand() {
        if (context.getChannelCommand() != null) {
            return context.getChannelCommand();
        } else {
            return config.getChannelCommand();
        }
    }

    public int getRemoteChannel() {
        return 0;
        // if (context.getRemoteChannel() != 0){
        // return context.getRemoteChannel();
        // } else {
        // return config.getRemoteChannel();
        // }
    }

    public String getServiceName() {
        return context.getServiceName().orElse(config.getServiceName());
    }
}
