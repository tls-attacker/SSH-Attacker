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

    // region Version Exchange
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

    // endregion

    // region Key Exchange Initialization
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

    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsServerToClient() {
        return context.getClientSupportedCipherAlgorithmsServerToClient().orElse(
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

    public List<String> getClientSupportedLanguagesClientToServer() {
        return context.getClientSupportedLanguagesClientToServer().orElse(
                config.getClientSupportedLanguagesClientToServer());
    }

    public List<String> getClientSupportedLanguagesServerToClient() {
        return context.getClientSupportedLanguagesServerToClient().orElse(
                config.getClientSupportedLanguagesServerToClient());
    }

    public List<String> getServerSupportedLanguagesServerToClient() {
        return context.getServerSupportedLanguagesServerToClient().orElse(
                config.getServerSupportedLanguagesServerToClient());
    }

    public List<String> getServerSupportedLanguagesClientToServer() {
        return context.getServerSupportedLanguagesClientToServer().orElse(
                config.getServerSupportedLanguagesClientToServer());
    }

    public boolean getClientFirstKeyExchangePacketFollows() {
        return context.getClientFirstKeyExchangePacketFollows().orElse(config.getClientFirstKeyExchangePacketFollows());
    }

    public boolean getServerFirstKeyExchangePacketFollows() {
        return context.getServerFirstKeyExchangePacketFollows().orElse(config.getServerFirstKeyExchangePacketFollows());
    }

    public int getClientReserved() {
        return context.getClientReserved().orElse(config.getClientReserved());
    }

    public int getServerReserved() {
        return context.getServerReserved().orElse(config.getServerReserved());
    }

    // endregion

    // region Key Exchange
    // TODO: Use config and context here
    @SuppressWarnings("SameReturnValue")
    public int getMinimalDHGroupSize() {
        return 2048;
    }

    @SuppressWarnings("SameReturnValue")
    public int getPreferredDHGroupSize() {
        return 4096;
    }

    @SuppressWarnings("SameReturnValue")
    public int getMaximalDHGroupSize() {
        return 8192;
    }

    // endregion

    public AuthenticationMethod getAuthenticationMethod() {
        return context.getAuthenticationMethod().orElse(config.getAuthenticationMethod());
    }

    public int getLocalChannel() {
        return context.getLocalChannel().orElse(config.getLocalChannel());
    }

    public ChannelType getChannelType() {
        return context.getChannelType().orElse(config.getChannelType());
    }

    public int getWindowSize() {
        return context.getWindowSize().orElse(config.getWindowSize());
    }

    public int getPacketSize() {
        return context.getPacketSize().orElse(config.getPacketSize());
    }
}
