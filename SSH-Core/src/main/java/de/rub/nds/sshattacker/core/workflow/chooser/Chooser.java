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
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.RsaKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpAbstractExtension;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.List;

public abstract class Chooser {

    protected final SshContext context;

    protected final Config config;

    protected Chooser(SshContext context, Config config) {
        super();
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

    public abstract List<LanguageTag> getClientSupportedLanguagesClientToServer();

    public abstract List<LanguageTag> getClientSupportedLanguagesServerToClient();

    public abstract List<LanguageTag> getServerSupportedLanguagesServerToClient();

    public abstract List<LanguageTag> getServerSupportedLanguagesClientToServer();

    public abstract boolean getClientFirstKeyExchangePacketFollows();

    public abstract boolean getServerFirstKeyExchangePacketFollows();

    public abstract int getClientReserved();

    public abstract int getServerReserved();

    // endregion

    // region SSH Extensions
    // section general extensions
    public abstract ArrayList<AbstractExtension<?>> getClientSupportedExtensions();

    public abstract ArrayList<AbstractExtension<?>> getServerSupportedExtensions();

    // section server-sig-algs extension
    public abstract List<PublicKeyAlgorithm>
            getServerSupportedPublicKeyAlgorithmsForAuthentication();

    public abstract SshPublicKey<?, ?> getSelectedPublicKeyForAuthentication();

    // section delay-compression extension
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
                ? getEncryptionAlgorithmClientToServer()
                : getEncryptionAlgorithmServerToClient();
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
                ? getEncryptionAlgorithmServerToClient()
                : getEncryptionAlgorithmClientToServer();
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
                ? getMacAlgorithmClientToServer()
                : getMacAlgorithmServerToClient();
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
                ? getMacAlgorithmServerToClient()
                : getMacAlgorithmClientToServer();
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
                ? getCompressionMethodClientToServer()
                : getCompressionMethodServerToClient();
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
                ? getCompressionMethodServerToClient()
                : getCompressionMethodClientToServer();
    }

    public abstract CompressionMethod getCompressionMethodClientToServer();

    public abstract CompressionMethod getCompressionMethodServerToClient();

    // endregion

    // region Key Exchange
    public abstract DhKeyExchange getDhKeyExchange();

    public abstract DhKeyExchange getDhGexKeyExchange();

    public abstract AbstractEcdhKeyExchange<?, ?> getEcdhKeyExchange();

    public abstract RsaKeyExchange getRsaKeyExchange();

    public abstract HybridKeyExchange getHybridKeyExchange();

    public abstract SshPublicKey<?, ?> getNegotiatedHostKey();

    public abstract Integer getMinimalDhGroupSize();

    public abstract Integer getPreferredDhGroupSize();

    public abstract Integer getMaximalDhGroupSize();

    // endregion

    // region Authentication

    public abstract AuthenticationMethod getAuthenticationMethod();

    public abstract ArrayList<AuthenticationResponseEntry> getNextPreConfiguredAuthResponses();

    public abstract ArrayList<AuthenticationPromptEntry> getNextPreConfiguredAuthPrompts();

    // endregion

    // region SFTP Version Exchange
    public abstract Integer getSftpClientVersion();

    public abstract Integer getSftpServerVersion();

    public abstract Integer getSftpNegotiatedVersion(boolean forParsing);

    // endregion

    // region SFTP Extensions
    // section general extensions
    public abstract ArrayList<SftpAbstractExtension<?>> getSftpClientSupportedExtensions();

    public abstract ArrayList<SftpAbstractExtension<?>> getSftpServerSupportedExtensions();

    // endregion

}
