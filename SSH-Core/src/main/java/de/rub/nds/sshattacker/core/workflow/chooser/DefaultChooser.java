/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.chooser;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;
import java.util.Optional;

public class DefaultChooser extends Chooser {
    public DefaultChooser(SshContext context, Config config) {
        super(context, config);
    }

    // region Version Exchange
    @Override
    public String getClientVersion() {
        return context.getClientVersion().orElse(config.getClientVersion());
    }

    @Override
    public String getClientComment() {
        return context.getClientComment().orElse(config.getClientComment());
    }

    @Override
    public String getServerVersion() {
        return context.getServerVersion().orElse(config.getServerVersion());
    }

    @Override
    public String getServerComment() {
        return context.getServerComment().orElse(config.getServerComment());
    }

    @Override
    public String getEndOfMessageSequence() {
        return context.getEndofMessageSequence().orElse(config.getEndOfMessageSequence());
    }

    // endregion

    // region Key Exchange Initialization
    @Override
    public byte[] getClientCookie() {
        return context.getClientCookie().orElse(config.getClientCookie());
    }

    @Override
    public byte[] getServerCookie() {
        return context.getServerCookie().orElse(config.getServerCookie());
    }

    @Override
    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        return context.getClientSupportedKeyExchangeAlgorithms()
                .orElse(config.getClientSupportedKeyExchangeAlgorithms());
    }

    @Override
    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        return context.getServerSupportedKeyExchangeAlgorithms()
                .orElse(config.getServerSupportedKeyExchangeAlgorithms());
    }

    @Override
    public List<PublicKeyAuthenticationAlgorithm> getClientSupportedHostKeyAlgorithms() {
        return context.getClientSupportedHostKeyAlgorithms()
                .orElse(config.getClientSupportedHostKeyAlgorithms());
    }

    @Override
    public List<PublicKeyAuthenticationAlgorithm> getServerSupportedHostKeyAlgorithms() {
        return context.getServerSupportedHostKeyAlgorithms()
                .orElse(config.getServerSupportedHostKeyAlgorithms());
    }

    @Override
    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsClientToServer() {
        return context.getClientSupportedCipherAlgorithmsClientToServer()
                .orElse(config.getClientSupportedCipherAlgorithmsClientToServer());
    }

    @Override
    public List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsServerToClient() {
        return context.getClientSupportedCipherAlgorithmsServerToClient()
                .orElse(config.getClientSupportedCipherAlgorithmsServerToClient());
    }

    @Override
    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsServerToClient() {
        return context.getServerSupportedCipherAlgorithmsServerToClient()
                .orElse(config.getServerSupportedCipherAlgorithmsServerToClient());
    }

    @Override
    public List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsClientToServer() {
        return context.getServerSupportedCipherAlgorithmsClientToServer()
                .orElse(config.getServerSupportedCipherAlgorithmsClientToServer());
    }

    @Override
    public List<MacAlgorithm> getClientSupportedMacAlgorithmsClientToServer() {
        return context.getClientSupportedMacAlgorithmsClientToServer()
                .orElse(config.getClientSupportedMacAlgorithmsClientToServer());
    }

    @Override
    public List<MacAlgorithm> getClientSupportedMacAlgorithmsServerToClient() {
        return context.getClientSupportedMacAlgorithmsServerToClient()
                .orElse(config.getClientSupportedMacAlgorithmsServerToClient());
    }

    @Override
    public List<MacAlgorithm> getServerSupportedMacAlgorithmsServerToClient() {
        return context.getServerSupportedMacAlgorithmsServerToClient()
                .orElse(config.getServerSupportedMacAlgorithmsServerToClient());
    }

    @Override
    public List<MacAlgorithm> getServerSupportedMacAlgorithmsClientToServer() {
        return context.getServerSupportedMacAlgorithmsClientToServer()
                .orElse(config.getServerSupportedMacAlgorithmsClientToServer());
    }

    @Override
    public List<CompressionMethod> getClientSupportedCompressionMethodsClientToServer() {
        return context.getClientSupportedCompressionMethodsClientToServer()
                .orElse(config.getClientSupportedCompressionMethodsClientToServer());
    }

    @Override
    public List<CompressionMethod> getClientSupportedCompressionMethodsServerToClient() {
        return context.getClientSupportedCompressionMethodsServerToClient()
                .orElse(config.getClientSupportedCompressionMethodsServerToClient());
    }

    @Override
    public List<CompressionMethod> getServerSupportedCompressionMethodsServerToClient() {
        return context.getServerSupportedCompressionMethodsServerToClient()
                .orElse(config.getServerSupportedCompressionMethodsServerToClient());
    }

    @Override
    public List<CompressionMethod> getServerSupportedCompressionMethodsClientToServer() {
        return context.getServerSupportedCompressionMethodsClientToServer()
                .orElse(config.getServerSupportedCompressionMethodsClientToServer());
    }

    @Override
    public List<String> getClientSupportedLanguagesClientToServer() {
        return context.getClientSupportedLanguagesClientToServer()
                .orElse(config.getClientSupportedLanguagesClientToServer());
    }

    @Override
    public List<String> getClientSupportedLanguagesServerToClient() {
        return context.getClientSupportedLanguagesServerToClient()
                .orElse(config.getClientSupportedLanguagesServerToClient());
    }

    @Override
    public List<String> getServerSupportedLanguagesServerToClient() {
        return context.getServerSupportedLanguagesServerToClient()
                .orElse(config.getServerSupportedLanguagesServerToClient());
    }

    @Override
    public List<String> getServerSupportedLanguagesClientToServer() {
        return context.getServerSupportedLanguagesClientToServer()
                .orElse(config.getServerSupportedLanguagesClientToServer());
    }

    @Override
    public boolean getClientFirstKeyExchangePacketFollows() {
        return context.getClientFirstKeyExchangePacketFollows()
                .orElse(config.getClientFirstKeyExchangePacketFollows());
    }

    @Override
    public boolean getServerFirstKeyExchangePacketFollows() {
        return context.getServerFirstKeyExchangePacketFollows()
                .orElse(config.getServerFirstKeyExchangePacketFollows());
    }

    @Override
    public int getClientReserved() {
        return context.getClientReserved().orElse(config.getClientReserved());
    }

    @Override
    public int getServerReserved() {
        return context.getServerReserved().orElse(config.getServerReserved());
    }

    // endregion

    // region Key Exchange
    // TODO: Use config and context here
    @SuppressWarnings("SameReturnValue")
    @Override
    public int getMinimalDHGroupSize() {
        return 2048;
    }

    @SuppressWarnings("SameReturnValue")
    @Override
    public int getPreferredDHGroupSize() {
        return 4096;
    }

    @SuppressWarnings("SameReturnValue")
    @Override
    public int getMaximalDHGroupSize() {
        return 8192;
    }

    @Override
    public DhKeyExchange getDHGexKeyExchange() {
        Optional<KeyExchange> keyExchange = context.getKeyExchangeInstance();
        if (keyExchange.isPresent()
                && keyExchange.get() instanceof DhKeyExchange
                && ((DhKeyExchange) keyExchange.get()).areGroupParametersSet()) {
            return (DhKeyExchange) keyExchange.get();
        } else {
            return new DhKeyExchange(config.getDefaultDHGexKeyExchangeGroup());
        }
    }

    @Override
    public RsaKeyExchange getRsaKeyExchange() {
        Optional<KeyExchange> keyExchange = context.getKeyExchangeInstance();
        if (keyExchange.isPresent()
                && keyExchange.get() instanceof RsaKeyExchange
                && ((RsaKeyExchange) keyExchange.get()).areParametersSet()) {
            return (RsaKeyExchange) keyExchange.get();
        } else {
            // Create default RsaKeyExchange from config
            RsaKeyExchange rsaKeyExchange = new RsaKeyExchange(config.getDefaultRsaPublicKey());
            rsaKeyExchange.setHashLength(config.getDefaultRsaKeyExchangeAlgorithm());
            return rsaKeyExchange;
        }
    }

    // endregion

    @Override
    public AuthenticationMethod getAuthenticationMethod() {
        return context.getAuthenticationMethod().orElse(config.getAuthenticationMethod());
    }
    // region connection
    @Override
    public int getLocalChannel() {
        return context.getLocalChannel().orElse(config.getLocalChannel());
    }

    @Override
    public ChannelType getChannelType() {
        return context.getChannelType().orElse(config.getChannelType());
    }

    @Override
    public int getWindowSize() {
        return context.getWindowSize().orElse(config.getWindowSize());
    }

    @Override
    public int getPacketSize() {
        return context.getPacketSize().orElse(config.getPacketSize());
    }

    @Override
    public int getRemoteChannel() {
        return context.getRemoteChannel().orElse(config.getRemoteChannel());
    }

    // endregion
}
