/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.chooser;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.kex.AbstractEcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;
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

    public abstract String getClientEndOfMessageSequence();

    public abstract String getServerVersion();

    public abstract String getServerComment();

    public abstract String getServerEndOfMessageSequence();
    // endregion

    // region Key Exchange Initialization
    public abstract byte[] getClientCookie();

    public abstract byte[] getServerCookie();

    public abstract List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms();

    public abstract List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms();

    public abstract List<PublicKeyAlgorithm> getClientSupportedHostKeyAlgorithms();

    public abstract List<PublicKeyAlgorithm> getServerSupportedHostKeyAlgorithms();

    public abstract List<EncryptionAlgorithm>
            getClientSupportedEncryptionAlgorithmsClientToServer();

    public abstract List<EncryptionAlgorithm>
            getClientSupportedEncryptionAlgorithmsServerToClient();

    public abstract List<EncryptionAlgorithm>
            getServerSupportedEncryptionAlgorithmsServerToClient();

    public abstract List<EncryptionAlgorithm>
            getServerSupportedEncryptionAlgorithmsClientToServer();

    public abstract List<MacAlgorithm> getClientSupportedMacAlgorithmsClientToServer();

    public abstract List<MacAlgorithm> getClientSupportedMacAlgorithmsServerToClient();

    public abstract List<MacAlgorithm> getServerSupportedMacAlgorithmsServerToClient();

    public abstract List<MacAlgorithm> getServerSupportedMacAlgorithmsClientToServer();

    public abstract List<CompressionMethod> getClientSupportedCompressionMethodsClientToServer();

    public abstract List<CompressionMethod> getClientSupportedCompressionMethodsServerToClient();

    public abstract List<CompressionMethod> getServerSupportedCompressionMethodsServerToClient();

    public abstract List<CompressionMethod> getServerSupportedCompressionMethodsClientToServer();

    public abstract List<String> getClientSupportedLanguagesClientToServer();

    public abstract List<String> getClientSupportedLanguagesServerToClient();

    public abstract List<String> getServerSupportedLanguagesServerToClient();

    public abstract List<String> getServerSupportedLanguagesClientToServer();

    public abstract boolean getClientFirstKeyExchangePacketFollows();

    public abstract boolean getServerFirstKeyExchangePacketFollows();

    public abstract int getClientReserved();

    public abstract int getServerReserved();
    // endregion

    // region SSH Extensions
    public abstract List<AbstractExtension<?>> getClientSupportedExtensions();

    public abstract List<AbstractExtension<?>> getServerSupportedExtensions();

    public abstract List<PublicKeyFormat>
            getServerSupportedPublicKeyAlgorithmsForAuthentification();

    public abstract List<CompressionMethod> getClientSupportedDelayCompressionMethods();

    public abstract List<CompressionMethod> getServerSupportedDelayCompressionMethods();
    // endregion

    // region Negotiated Parameters
    public abstract KeyExchangeAlgorithm getKeyExchangeAlgorithm();

    public abstract PublicKeyAlgorithm getHostKeyAlgorithm();

    /**
     * Returns the encryption algorithm for outgoing packets (send). Internally, this either calls
     * getEncryptionAlgorithmClientToServer() or getEncryptionAlgorithmServerToClient(), depending
     * on the role of SSH-Attacker in the current context.
     *
     * @return The negotiated encryption algorithm for outgoing packets.
     */
    public EncryptionAlgorithm getSendEncryptionAlgorithm() {
        return context.isClient()
                ? this.getEncryptionAlgorithmClientToServer()
                : this.getEncryptionAlgorithmServerToClient();
    }

    /**
     * Returns the encryption algorithm for incoming packets (receive). Internally, this either
     * calls getMacAlgorithmClientToServer() or getMacAlgorithmServerToClient(), depending on the
     * role of SSH-Attacker in the current context.
     *
     * @return The negotiated encryption algorithm for incoming packets.
     */
    public EncryptionAlgorithm getReceiveEncryptionAlgorithm() {
        return context.isClient()
                ? this.getEncryptionAlgorithmServerToClient()
                : this.getEncryptionAlgorithmClientToServer();
    }

    public abstract EncryptionAlgorithm getEncryptionAlgorithmClientToServer();

    public abstract EncryptionAlgorithm getEncryptionAlgorithmServerToClient();

    /**
     * Returns the MAC algorithm for outgoing packets (send). Internally, this either calls
     * getMacAlgorithmClientToServer() or getMacAlgorithmServerToClient(), depending on the role of
     * SSH-Attacker in the current context.
     *
     * @return The negotiated MAC algorithm for outgoing packets.
     */
    public MacAlgorithm getSendMacAlgorithm() {
        return context.isClient()
                ? this.getMacAlgorithmClientToServer()
                : this.getMacAlgorithmServerToClient();
    }

    /**
     * Returns the MAC algorithm for incoming packets (receive). Internally, this either calls
     * getMacAlgorithmClientToServer() or getMacAlgorithmServerToClient(), depending on the role of
     * SSH-Attacker in the current context.
     *
     * @return The negotiated MAC algorithm for incoming packets.
     */
    public MacAlgorithm getReceiveMacAlgorithm() {
        return context.isClient()
                ? this.getMacAlgorithmServerToClient()
                : this.getMacAlgorithmClientToServer();
    }

    public abstract MacAlgorithm getMacAlgorithmClientToServer();

    public abstract MacAlgorithm getMacAlgorithmServerToClient();

    /**
     * Returns the compression method for outgoing packets (send). Internally, this method either
     * calls getCompressionMethodClientToServer() or getCompressionMethodServerToClient(), depending
     * on the role of SSH-Attacker in the current context.
     *
     * @return The negotiated compression method for outgoing packets.
     */
    public CompressionMethod getSendCompressionMethod() {
        return context.isClient()
                ? this.getCompressionMethodClientToServer()
                : this.getCompressionMethodServerToClient();
    }

    /**
     * Returns the compression method for incoming packets (receive). Internally, this method either
     * calls getCompressionMethodClientToServer() or getCompressionMethodServerToClient(), depending
     * on the role of SSH-Attacker in the current context.
     *
     * @return The negotiated compression method for incoming packets.
     */
    public CompressionMethod getReceiveCompressionMethod() {
        return context.isClient()
                ? this.getCompressionMethodServerToClient()
                : this.getCompressionMethodClientToServer();
    }

    public abstract CompressionMethod getCompressionMethodClientToServer();

    public abstract CompressionMethod getCompressionMethodServerToClient();
    // endregion

    // region Key Exchange
    public abstract DhKeyExchange getDhKeyExchange();

    public abstract DhKeyExchange getDhGexKeyExchange();

    public abstract AbstractEcdhKeyExchange getEcdhKeyExchange();

    public abstract RsaKeyExchange getRsaKeyExchange();

    public abstract SshPublicKey<?, ?> getNegotiatedHostKey();

    public abstract Integer getMinimalDhGroupSize();

    public abstract Integer getPreferredDhGroupSize();

    public abstract Integer getMaximalDhGroupSize();
    // endregion

    public abstract AuthenticationMethod getAuthenticationMethod();
}
