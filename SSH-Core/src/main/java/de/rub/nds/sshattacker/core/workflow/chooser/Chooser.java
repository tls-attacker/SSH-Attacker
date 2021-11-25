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
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Chooser {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final SshContext context;

    protected final Config config;

    public Chooser(SshContext context, Config config) {
        this.config = config;
        this.context = context;
    }

    public Config getConfig() {
        return config;
    }

    public SshContext getContext() {
        return context;
    }

    // region Version Exchange
    public abstract String getClientVersion();

    public abstract String getClientComment();

    public abstract String getServerVersion();

    public abstract String getServerComment();

    public abstract String getEndOfMessageSequence();
    // endregion

    // region Key Exchange Initialization
    public abstract byte[] getClientCookie();

    public abstract byte[] getServerCookie();

    public abstract List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms();

    public abstract List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms();

    public abstract List<PublicKeyAuthenticationAlgorithm> getClientSupportedHostKeyAlgorithms();

    public abstract List<PublicKeyAuthenticationAlgorithm> getServerSupportedHostKeyAlgorithms();

    public abstract List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsClientToServer();

    public abstract List<EncryptionAlgorithm> getClientSupportedCipherAlgorithmsServerToClient();

    public abstract List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsServerToClient();

    public abstract List<EncryptionAlgorithm> getServerSupportedCipherAlgorithmsClientToServer();

    public abstract List<MacAlgorithm> getClientSupportedMacAlgorithmsClientToServer();

    public abstract List<MacAlgorithm> getClientSupportedMacAlgorithmsServerToClient();

    public abstract List<MacAlgorithm> getServerSupportedMacAlgorithmsServerToClient();

    public abstract List<MacAlgorithm> getServerSupportedMacAlgorithmsClientToServer();

    public abstract List<CompressionAlgorithm>
            getClientSupportedCompressionAlgorithmsClientToServer();

    public abstract List<CompressionAlgorithm>
            getClientSupportedCompressionAlgorithmsServerToClient();

    public abstract List<CompressionAlgorithm>
            getServerSupportedCompressionAlgorithmsServerToClient();

    public abstract List<CompressionAlgorithm>
            getServerSupportedCompressionAlgorithmsClientToServer();

    public abstract List<String> getClientSupportedLanguagesClientToServer();

    public abstract List<String> getClientSupportedLanguagesServerToClient();

    public abstract List<String> getServerSupportedLanguagesServerToClient();

    public abstract List<String> getServerSupportedLanguagesClientToServer();

    public abstract boolean getClientFirstKeyExchangePacketFollows();

    public abstract boolean getServerFirstKeyExchangePacketFollows();

    public abstract int getClientReserved();

    public abstract int getServerReserved();

    // endregion

    // region Key Exchange
    // TODO: Use config and context here
    @SuppressWarnings("SameReturnValue")
    public abstract int getMinimalDHGroupSize();

    @SuppressWarnings("SameReturnValue")
    public abstract int getPreferredDHGroupSize();

    @SuppressWarnings("SameReturnValue")
    public abstract int getMaximalDHGroupSize();

    public abstract List<KeyExchangeAlgorithm> getAllSupportedDHKeyExchange();

    public abstract List<KeyExchangeAlgorithm> getAllSupportedDH_DHGEKeyExchange();

    public abstract KeyExchangeAlgorithm getRandomKeyExchangeAlgorithm(
            Random random, List<KeyExchangeAlgorithm> possibleKeyExchangeAlgorithms);

    // endregion

    public abstract AuthenticationMethod getAuthenticationMethod();

    public abstract int getLocalChannel();

    public abstract ChannelType getChannelType();

    public abstract int getWindowSize();

    public abstract int getPacketSize();

    public abstract int getRemoteChannel();
}
