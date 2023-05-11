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
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A default implementation of the abstract Chooser class. Values will be primarily provided from
 * context or, if no context value is available, from the provided Config instance. The JavaDoc of
 * each Chooser method provides detailed information on the Config fallback behaviour of the method.
 */
public class DefaultChooser extends Chooser {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Constructs a new instance of the DefaultChooser class with the given context and config.
     *
     * @param context Context of the SSH connection
     * @param config Configuration of the SSH-Attacker
     */
    public DefaultChooser(SshContext context, Config config) {
        super(context, config);
    }

    // region Version Exchange
    /**
     * Retrieves the client version string from context. If no version string was received (i.e.
     * out-of-order workflow or SSH-Attacker is running in client mode), the client version string
     * from config will be returned.
     *
     * @return The SSH version string of the client
     */
    @Override
    public String getClientVersion() {
        return context.getClientVersion().orElse(config.getClientVersion());
    }

    /**
     * Retrieves the client comment string from context. If no comment string was received (i.e.
     * out-of-order workflow or SSH-Attacker is running in client mode), the client comment string
     * from config will be returned.
     *
     * @return The SSH comment string of the client
     */
    @Override
    public String getClientComment() {
        return context.getClientComment().orElse(config.getClientComment());
    }

    /**
     * Retrieves the client end-of-message sequence from context. If no such sequence was received
     * (i.e. out-of-order workflow or SSH-Attacker is running in client mode), the client
     * end-of-message sequence from config will be returned.
     *
     * @return The end-of-message sequence of the client
     */
    @Override
    public String getClientEndOfMessageSequence() {
        return context.getClientEndOfMessageSequence()
                .orElse(config.getClientEndOfMessageSequence());
    }

    /**
     * Retrieves the server version string from context. If no version string was received (i.e.
     * out-of-order workflow or SSH-Attacker is running in server mode), the server version string
     * from config will be returned.
     *
     * @return The SSH version string of the server
     */
    @Override
    public String getServerVersion() {
        return context.getServerVersion().orElse(config.getServerVersion());
    }

    /**
     * Retrieves the server comment string from context. If no comment string was received (i.e.
     * out-of-order workflow or SSH-Attacker is running in server mode), the server comment string
     * from config will be returned.
     *
     * @return The SSH comment string of the server
     */
    @Override
    public String getServerComment() {
        return context.getServerComment().orElse(config.getServerComment());
    }

    /**
     * Retrieves the server end-of-message sequence from context. If no such sequence was received
     * (i.e. out-of-order workflow or SSH-Attacker is running in server mode), the server
     * end-of-message sequence from config will be returned.
     *
     * @return The end-of-message sequence of the server
     */
    @Override
    public String getServerEndOfMessageSequence() {
        return context.getServerEndOfMessageSequence()
                .orElse(config.getServerEndOfMessageSequence());
    }
    // endregion

    // region Key Exchange Initialization
    /**
     * Retrieves the client cookie from context. If no cookie was received (i. e. out-of-order
     * workflow or SSH-Attacker is running in client mode), the client cookie from config will be
     * returned instead.
     *
     * @return The key exchange cookie of the client
     */
    @Override
    public byte[] getClientCookie() {
        return context.getClientCookie().orElse(config.getClientCookie());
    }

    /**
     * Retrieves the server cookie from context. If no cookie was received (i. e. out-of-order
     * workflow or SSH-Attacker is running in server mode), the server cookie from config will be
     * returned instead.
     *
     * @return The key exchange cookie of the server
     */
    @Override
    public byte[] getServerCookie() {
        return context.getServerCookie().orElse(config.getServerCookie());
    }

    /**
     * Retrieves the list of key exchange algorithms supported by the server from context. If no
     * SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in client mode, the client
     * supported key exchange algorithms from config will be returned instead.
     *
     * @return A list of key exchange algorithms supported by the client
     */
    @Override
    public List<KeyExchangeAlgorithm> getClientSupportedKeyExchangeAlgorithms() {
        return context.getClientSupportedKeyExchangeAlgorithms()
                .orElse(config.getClientSupportedKeyExchangeAlgorithms());
    }

    /**
     * Retrieves the list of key exchange algorithms supported by the server from context. If no
     * SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in server mode, the server
     * supported key exchange algorithms from config will be returned instead.
     *
     * @return A list of key exchange algorithms supported by the server
     */
    @Override
    public List<KeyExchangeAlgorithm> getServerSupportedKeyExchangeAlgorithms() {
        return context.getServerSupportedKeyExchangeAlgorithms()
                .orElse(config.getServerSupportedKeyExchangeAlgorithms());
    }

    /**
     * Retrieves the list of host key algorithms supported by the client from context. If no
     * SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in client mode, the client
     * supported host key algorithms from config will be returned instead.
     *
     * @return A list of host key algorithms supported by the client
     */
    @Override
    public List<PublicKeyAlgorithm> getClientSupportedHostKeyAlgorithms() {
        return context.getClientSupportedHostKeyAlgorithms()
                .orElse(config.getClientSupportedHostKeyAlgorithms());
    }

    /**
     * Retrieves the list of host key algorithms supported by the server from context. If no
     * SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in server mode, the server
     * supported host key algorithms from config will be returned instead.
     *
     * @return A list of host key algorithms supported by the server
     */
    @Override
    public List<PublicKeyAlgorithm> getServerSupportedHostKeyAlgorithms() {
        return context.getServerSupportedHostKeyAlgorithms()
                .orElse(config.getServerSupportedHostKeyAlgorithms());
    }

    /**
     * Retrieves the list of encryption algorithms supported by the client for client to server
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in client mode, the list of client supported client to server encryption algorithms
     * from config will be returned instead.
     *
     * @return A list of encryption algorithms for client to server communication supported by the
     *     client
     */
    @Override
    public List<EncryptionAlgorithm> getClientSupportedEncryptionAlgorithmsClientToServer() {
        return context.getClientSupportedEncryptionAlgorithmsClientToServer()
                .orElse(config.getClientSupportedEncryptionAlgorithmsClientToServer());
    }

    /**
     * Retrieves the list of encryption algorithms supported by the client for server to client
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in client mode, the list of client supported server to client encryption algorithms
     * from config will be returned instead.
     *
     * @return A list of encryption algorithms for server to client communication supported by the
     *     client
     */
    @Override
    public List<EncryptionAlgorithm> getClientSupportedEncryptionAlgorithmsServerToClient() {
        return context.getClientSupportedEncryptionAlgorithmsServerToClient()
                .orElse(config.getClientSupportedEncryptionAlgorithmsServerToClient());
    }

    /**
     * Retrieves the list of encryption algorithms supported by the server for server to client
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in server mode, the list of server supported server to client encryption algorithms
     * from config will be returned instead.
     *
     * @return A list of encryption algorithms for server to client communication supported by the
     *     server
     */
    @Override
    public List<EncryptionAlgorithm> getServerSupportedEncryptionAlgorithmsServerToClient() {
        return context.getServerSupportedEncryptionAlgorithmsServerToClient()
                .orElse(config.getServerSupportedEncryptionAlgorithmsServerToClient());
    }

    /**
     * Retrieves the list of encryption algorithms supported by the server for client to server
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in server mode, the list of server supported client to server encryption algorithms
     * from config will be returned instead.
     *
     * @return A list of encryption algorithms for client to server communication supported by the
     *     server
     */
    @Override
    public List<EncryptionAlgorithm> getServerSupportedEncryptionAlgorithmsClientToServer() {
        return context.getServerSupportedEncryptionAlgorithmsClientToServer()
                .orElse(config.getServerSupportedEncryptionAlgorithmsClientToServer());
    }

    /**
     * Retrieves the list of MAC algorithms supported by the client for client to server
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in client mode, the list of client supported client to server MAC algorithms from
     * config will be returned instead.
     *
     * @return A list of MAC algorithms for client to server communication supported by the client
     */
    @Override
    public List<MacAlgorithm> getClientSupportedMacAlgorithmsClientToServer() {
        return context.getClientSupportedMacAlgorithmsClientToServer()
                .orElse(config.getClientSupportedMacAlgorithmsClientToServer());
    }

    /**
     * Retrieves the list of MAC algorithms supported by the client for server to client
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in client mode, the list of client supported server to client MAC algorithms from
     * config will be returned instead.
     *
     * @return A list of MAC algorithms for server to client communication supported by the client
     */
    @Override
    public List<MacAlgorithm> getClientSupportedMacAlgorithmsServerToClient() {
        return context.getClientSupportedMacAlgorithmsServerToClient()
                .orElse(config.getClientSupportedMacAlgorithmsServerToClient());
    }

    /**
     * Retrieves the list of MAC algorithms supported by the server for server to client
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in server mode, the list of server supported server to client MAC algorithms from
     * config will be returned instead.
     *
     * @return A list of MAC algorithms for server to client communication supported by the server
     */
    @Override
    public List<MacAlgorithm> getServerSupportedMacAlgorithmsServerToClient() {
        return context.getServerSupportedMacAlgorithmsServerToClient()
                .orElse(config.getServerSupportedMacAlgorithmsServerToClient());
    }

    /**
     * Retrieves the list of MAC algorithms supported by the server for client to server
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in server mode, the list of server supported client to server MAC algorithms from
     * config will be returned instead.
     *
     * @return A list of MAC algorithms for client to server communication supported by the server
     */
    @Override
    public List<MacAlgorithm> getServerSupportedMacAlgorithmsClientToServer() {
        return context.getServerSupportedMacAlgorithmsClientToServer()
                .orElse(config.getServerSupportedMacAlgorithmsClientToServer());
    }

    /**
     * Retrieves the list of compression algorithms supported by the client for client to server
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in client mode, the list of client supported client to server compression algorithms
     * from config will be returned instead.
     *
     * @return A list of compression algorithms for client to server communication supported by the
     *     client
     */
    @Override
    public List<CompressionMethod> getClientSupportedCompressionMethodsClientToServer() {
        return context.getClientSupportedCompressionMethodsClientToServer()
                .orElse(config.getClientSupportedCompressionMethodsClientToServer());
    }

    /**
     * Retrieves the list of compression algorithms supported by the client for server to client
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in client mode, the list of client supported server to client compression algorithms
     * from config will be returned instead.
     *
     * @return A list of compression algorithms for server to client communication supported by the
     *     client
     */
    @Override
    public List<CompressionMethod> getClientSupportedCompressionMethodsServerToClient() {
        return context.getClientSupportedCompressionMethodsServerToClient()
                .orElse(config.getClientSupportedCompressionMethodsServerToClient());
    }

    /**
     * Retrieves the list of compression algorithms supported by the server for server to client
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in server mode, the list of server supported server to client compression algorithms
     * from config will be returned instead.
     *
     * @return A list of compression algorithms for server to client communication supported by the
     *     server
     */
    @Override
    public List<CompressionMethod> getServerSupportedCompressionMethodsServerToClient() {
        return context.getServerSupportedCompressionMethodsServerToClient()
                .orElse(config.getServerSupportedCompressionMethodsServerToClient());
    }

    /**
     * Retrieves the list of compression algorithms supported by the server for client to server
     * communication from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is
     * running in server mode, the list of server supported client to server compression algorithms
     * from config will be returned instead.
     *
     * @return A list of compression algorithms for client to server communication supported by the
     *     server
     */
    @Override
    public List<CompressionMethod> getServerSupportedCompressionMethodsClientToServer() {
        return context.getServerSupportedCompressionMethodsClientToServer()
                .orElse(config.getServerSupportedCompressionMethodsClientToServer());
    }

    /**
     * Retrieves the list of languages supported by the client for client to server communication
     * from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in
     * client mode, the list of client supported client to server languages from config will be
     * returned instead.
     *
     * @return A list of languages for client to server communication supported by the client
     */
    @Override
    public List<String> getClientSupportedLanguagesClientToServer() {
        return context.getClientSupportedLanguagesClientToServer()
                .orElse(config.getClientSupportedLanguagesClientToServer());
    }

    /**
     * Retrieves the list of languages supported by the client for server to client communication
     * from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in
     * client mode, the list of client supported server to client languages from config will be
     * returned instead.
     *
     * @return A list of languages for server to client communication supported by the client
     */
    @Override
    public List<String> getClientSupportedLanguagesServerToClient() {
        return context.getClientSupportedLanguagesServerToClient()
                .orElse(config.getClientSupportedLanguagesServerToClient());
    }

    /**
     * Retrieves the list of languages supported by the server for server to client communication
     * from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in
     * server mode, the list of server supported server to client languages from config will be
     * returned instead.
     *
     * @return A list of languages for server to client communication supported by the server
     */
    @Override
    public List<String> getServerSupportedLanguagesServerToClient() {
        return context.getServerSupportedLanguagesServerToClient()
                .orElse(config.getServerSupportedLanguagesServerToClient());
    }

    /**
     * Retrieves the list of languages supported by the server for client to server communication
     * from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in
     * server mode, the list of server supported client to server languages from config will be
     * returned instead.
     *
     * @return A list of languages for client to server communication supported by the server
     */
    @Override
    public List<String> getServerSupportedLanguagesClientToServer() {
        return context.getServerSupportedLanguagesClientToServer()
                .orElse(config.getServerSupportedLanguagesClientToServer());
    }

    /**
     * Retrieves the value of the guessed key exchange flag as included in the clients
     * SSH_MSG_KEXINIT packet from context. If no SSH_MSG_KEXINIT packet was received yet or
     * SSH-Attacker is running in client mode, the value from config will be returned instead.
     *
     * @return A boolean flag indicating whether the client will initiate a guessed key exchange by
     *     sending the first key exchange packet ahead of time. For details see RFC 4253 Section
     *     7.1.
     */
    @Override
    public boolean getClientFirstKeyExchangePacketFollows() {
        return context.getClientFirstKeyExchangePacketFollows()
                .orElse(config.getClientFirstKeyExchangePacketFollows());
    }

    /**
     * Retrieves the value of the guessed key exchange flag as included in the servers
     * SSH_MSG_KEXINIT packet from context. If no SSH_MSG_KEXINIT packet was received yet or
     * SSH-Attacker is running in server mode, the value from config will be returned instead.
     *
     * @return A boolean flag indicating whether the server will initiate a guessed key exchange by
     *     sending the first key exchange packet ahead of time. For details see RFC 4253 Section
     *     7.1.
     */
    @Override
    public boolean getServerFirstKeyExchangePacketFollows() {
        return context.getServerFirstKeyExchangePacketFollows()
                .orElse(config.getServerFirstKeyExchangePacketFollows());
    }

    /**
     * Retrieves the value of the reserved field as included in the clients SSH_MSG_KEXINIT packet
     * from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in
     * client mode, the value from config will be returned instead.
     *
     * @return The value of the clients reserved field
     */
    @Override
    public int getClientReserved() {
        return context.getClientReserved().orElse(config.getClientReserved());
    }

    /**
     * Retrieves the value of the reserved field as included in the servers SSH_MSG_KEXINIT packet
     * from context. If no SSH_MSG_KEXINIT packet was received yet or SSH-Attacker is running in
     * server mode, the value from config will be returned instead.
     *
     * @return The value of the servers reserved field
     */
    @Override
    public int getServerReserved() {
        return context.getServerReserved().orElse(config.getServerReserved());
    }
    // endregion

    // region SSH Extensions
    /**
     * Retrieves the list of client supported extensions included in the clients SSH_MSG_EXT_INFO
     * packet from context. If no SSH_MSG_EXT_INFO packet was received yet or SSH-Attacker is
     * running in client mode, the extensions from config will be returned instead.
     *
     * @return List of client supported extensions
     */
    public List<AbstractExtension<?>> getClientSupportedExtensions() {
        return context.getClientSupportedExtensions().orElse(config.getClientSupportedExtensions());
    }

    /**
     * Retrieves the list of server supported extensions included in the servers SSH_MSG_EXT_INFO
     * packet from context. If no SSH_MSG_EXT_INFO packet was received yet or SSH-Attacker is
     * running in server mode, the extensions from config will be returned instead.
     *
     * @return List of server supported extensions
     */
    public List<AbstractExtension<?>> getServerSupportedExtensions() {
        return context.getServerSupportedExtensions().orElse(config.getServerSupportedExtensions());
    }

    /**
     * Retrieves the list of server supported public key algorithms for authentication of the
     * server-sig-algs extension included in SSH_MSG_EXT_INFO packet from context. If no
     * SSH_MSG_EXT_INFO packet was received yet or SSH-Attacker is running in server mode, the
     * extension from config will be returned instead.
     *
     * @return List of server supported public key algorithms for authentication
     */
    public List<PublicKeyAlgorithm> getServerSupportedPublicKeyAlgorithmsForAuthentication() {
        return context.getServerSupportedPublicKeyAlgorithmsForAuthentication()
                .orElse(config.getServerSupportedPublicKeyAlgorithmsForAuthentication());
    }

    /**
     * Retrieves the public key to use for client authentication. If no server-sig-algs extension
     * was received yet or server-sig-algs extension is disabled in config, the first user key from
     * config(SSH_RSA) is returned.
     */
    public SshPublicKey<?, ?> getSelectedPublicKeyForAuthentication() {
        // server-sig-algs extension is disabled or no server-sig-algs extension received yet ?
        // -> use first user key(SSH_RSA)
        if (!config.getRespectServerSigAlgsExtension()
                || !context.getServerSigAlgsExtensionReceivedFromServer()) {
            return config.getUserKeys().get(0);
        }

        // get client supported public key algorithms
        List<PublicKeyAlgorithm> clientSupportedPublicKeyAlgorithms =
                config.getUserKeys().stream()
                        .map(
                                algorithm ->
                                        PublicKeyAlgorithm.fromName(
                                                algorithm.getPublicKeyFormat().getName()))
                        .collect(Collectors.toList());

        // get server supported public key algorithms
        // no server-sig-algs extension received? -> SSH_RSA
        List<PublicKeyAlgorithm> serverSupportedPublicKeyAlgorithms =
                context.getServerSupportedPublicKeyAlgorithmsForAuthentication()
                        .orElse(List.of(PublicKeyAlgorithm.SSH_RSA));

        // determine common public key algorithm to use for client authentication
        PublicKeyAlgorithm commonPublicKeyAlgorithm =
                AlgorithmPicker.pickAlgorithm(
                                clientSupportedPublicKeyAlgorithms,
                                serverSupportedPublicKeyAlgorithms)
                        .orElse(PublicKeyAlgorithm.SSH_RSA);

        // get public key of negotiated public key algorithm
        // no match? -> use first user key(SSH_RSA)
        SshPublicKey<?, ?> publicKey =
                config.getUserKeys().stream()
                        .filter(
                                key ->
                                        PublicKeyAlgorithm.fromName(
                                                        key.getPublicKeyFormat().getName())
                                                .equals(commonPublicKeyAlgorithm))
                        .collect(Collectors.toList())
                        .get(0);
        return publicKey;
    }

    /**
     * Retrieves the list of client supported compression methods of the delay-compression extension
     * included in SSH_MSG_EXT_INFO packet from context. If no SSH_MSG_EXT_INFO packet was received
     * yet or SSH-Attacker is running in client mode, the extension from config will be returned
     * instead.
     *
     * @return List of client supported compression methods
     */
    public List<CompressionMethod> getClientSupportedDelayCompressionMethods() {
        return context.getClientSupportedDelayCompressionMethods()
                .orElse(config.getClientSupportedDelayCompressionMethods());
    }

    /**
     * Retrieves the list of server supported compression methods of the delay-compression extension
     * included in SSH_MSG_EXT_INFO packet from context. If no SSH_MSG_EXT_INFO packet was received
     * yet or SSH-Attacker is running in server mode, the extension from config will be returned
     * instead.
     *
     * @return List of server supported compression methods
     */
    public List<CompressionMethod> getServerSupportedDelayCompressionMethods() {
        return context.getServerSupportedDelayCompressionMethods()
                .orElse(config.getServerSupportedDelayCompressionMethods());
    }
    // endregion

    // region Negotiated Parameters
    /**
     * Retrieves the negotiated key exchange algorithm from context. If the field is not set in
     * context, this method will try to pick the negotiated algorithm according to RFC 4253 based on
     * the lists of supported algorithms and update the context accordingly. If the supported
     * algorithms lists of client and server do not intersect, this method will return the first
     * algorithm in the list sent by SSH-Attacker.
     *
     * @return The negotiated key exchange algorithm
     */
    @Override
    public KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
        return context.getKeyExchangeAlgorithm()
                .orElseGet(
                        () -> {
                            KeyExchangeAlgorithm negotiatedAlgorithm =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this.getClientSupportedKeyExchangeAlgorithms(),
                                                    this.getServerSupportedKeyExchangeAlgorithms())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedKeyExchangeAlgorithms()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedKeyExchangeAlgorithms()
                                                                    .get(0));
                            // TODO: Determine whether updating the context here can be considered
                            // useful or disadvantageous (same for all negotiated algorithm methods)
                            context.setKeyExchangeAlgorithm(negotiatedAlgorithm);
                            return negotiatedAlgorithm;
                        });
    }

    /**
     * Retrieves the negotiated host key algorithm from context. If the field is not set in context,
     * this method will try to pick the negotiated algorithm according to RFC 4253 based on the
     * lists of supported algorithms and update the context accordingly. If the supported algorithms
     * lists of client and server do not intersect, this method will return the first algorithm in
     * the list sent by SSH-Attacker.
     *
     * @return The negotiated host key algorithm
     */
    @Override
    public PublicKeyAlgorithm getHostKeyAlgorithm() {
        return context.getHostKeyAlgorithm()
                .orElseGet(
                        () -> {
                            PublicKeyAlgorithm negotiatedAlgorithm =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this.getClientSupportedHostKeyAlgorithms(),
                                                    this.getServerSupportedHostKeyAlgorithms())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedHostKeyAlgorithms()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedHostKeyAlgorithms()
                                                                    .get(0));
                            context.setHostKeyAlgorithm(negotiatedAlgorithm);
                            return negotiatedAlgorithm;
                        });
    }

    /**
     * Retrieves the negotiated encryption algorithm for client to server communication from
     * context. If the field is not set in context, this method will try to pick the negotiated
     * algorithm according to RFC 4253 based on the lists of supported algorithms and update the
     * context accordingly. If the supported algorithms lists of client and server do not intersect,
     * this method will return the first algorithm in the list sent by SSH-Attacker.
     *
     * @return The negotiated encryption algorithm for client to server communication
     */
    @Override
    public EncryptionAlgorithm getEncryptionAlgorithmClientToServer() {
        return context.getEncryptionAlgorithmClientToServer()
                .orElseGet(
                        () -> {
                            EncryptionAlgorithm negotiatedAlgorithm =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this
                                                            .getClientSupportedEncryptionAlgorithmsClientToServer(),
                                                    this
                                                            .getServerSupportedEncryptionAlgorithmsClientToServer())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedEncryptionAlgorithmsClientToServer()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedEncryptionAlgorithmsClientToServer()
                                                                    .get(0));
                            context.setEncryptionAlgorithmClientToServer(negotiatedAlgorithm);
                            return negotiatedAlgorithm;
                        });
    }

    /**
     * Retrieves the negotiated encryption algorithm for server to client communication from
     * context. If the field is not set in context, this method will try to pick the negotiated
     * algorithm according to RFC 4253 based on the lists of supported algorithms and update the
     * context accordingly. If the supported algorithms lists of client and server do not intersect,
     * this method will return the first algorithm in the list sent by SSH-Attacker.
     *
     * @return The negotiated encryption algorithm for server to client communication
     */
    @Override
    public EncryptionAlgorithm getEncryptionAlgorithmServerToClient() {
        return context.getEncryptionAlgorithmServerToClient()
                .orElseGet(
                        () -> {
                            EncryptionAlgorithm negotiatedAlgorithm =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this
                                                            .getClientSupportedEncryptionAlgorithmsServerToClient(),
                                                    this
                                                            .getServerSupportedEncryptionAlgorithmsServerToClient())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedEncryptionAlgorithmsServerToClient()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedEncryptionAlgorithmsServerToClient()
                                                                    .get(0));
                            context.setEncryptionAlgorithmServerToClient(negotiatedAlgorithm);
                            return negotiatedAlgorithm;
                        });
    }

    /**
     * Retrieves the negotiated MAC algorithm for client to server communication from context. If
     * the field is not set in context, this method will try to pick the negotiated algorithm
     * according to RFC 4253 based on the lists of supported algorithms and update the context
     * accordingly. If the supported algorithms lists of client and server do not intersect, this
     * method will return the first algorithm in the list sent by SSH-Attacker.
     *
     * @return The negotiated MAC algorithm for client to server communication
     */
    @Override
    public MacAlgorithm getMacAlgorithmClientToServer() {
        return context.getMacAlgorithmClientToServer()
                .orElseGet(
                        () -> {
                            MacAlgorithm negotiatedAlgorithm =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this
                                                            .getClientSupportedMacAlgorithmsClientToServer(),
                                                    this
                                                            .getServerSupportedMacAlgorithmsClientToServer())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedMacAlgorithmsClientToServer()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedMacAlgorithmsClientToServer()
                                                                    .get(0));
                            context.setMacAlgorithmClientToServer(negotiatedAlgorithm);
                            return negotiatedAlgorithm;
                        });
    }

    /**
     * Retrieves the negotiated MAC algorithm for server to client communication from context. If
     * the field is not set in context, this method will try to pick the negotiated algorithm
     * according to RFC 4253 based on the lists of supported algorithms and update the context
     * accordingly. If the supported algorithms lists of client and server do not intersect, this
     * method will return the first algorithm in the list sent by SSH-Attacker.
     *
     * @return The negotiated MAC algorithm for server to client communication
     */
    @Override
    public MacAlgorithm getMacAlgorithmServerToClient() {
        return context.getMacAlgorithmServerToClient()
                .orElseGet(
                        () -> {
                            MacAlgorithm negotiatedAlgorithm =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this
                                                            .getClientSupportedMacAlgorithmsServerToClient(),
                                                    this
                                                            .getServerSupportedMacAlgorithmsServerToClient())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedMacAlgorithmsServerToClient()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedMacAlgorithmsServerToClient()
                                                                    .get(0));
                            context.setMacAlgorithmServerToClient(negotiatedAlgorithm);
                            return negotiatedAlgorithm;
                        });
    }

    /**
     * Retrieves the negotiated compression method for client to server communication from context.
     * If the field is not set in context, this method will try to pick the negotiated algorithm
     * according to RFC 4253 based on the lists of supported algorithms and update the context
     * accordingly. If the supported algorithms lists of client and server do not intersect, this
     * method will return the first algorithm in the list sent by SSH-Attacker.
     *
     * @return The negotiated compression method for client to server communication
     */
    @Override
    public CompressionMethod getCompressionMethodClientToServer() {
        return context.getCompressionMethodClientToServer()
                .orElseGet(
                        () -> {
                            CompressionMethod negotiatedMethod =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this
                                                            .getClientSupportedCompressionMethodsClientToServer(),
                                                    this
                                                            .getServerSupportedCompressionMethodsClientToServer())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedCompressionMethodsClientToServer()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedCompressionMethodsClientToServer()
                                                                    .get(0));
                            context.setCompressionMethodClientToServer(negotiatedMethod);
                            return negotiatedMethod;
                        });
    }

    /**
     * Retrieves the negotiated compression method for server to client communication from context.
     * If the field is not set in context, this method will try to pick the negotiated algorithm
     * according to RFC 4253 based on the lists of supported algorithms and update the context
     * accordingly. If the supported algorithms lists of client and server do not intersect, this
     * method will return the first algorithm in the list sent by SSH-Attacker.
     *
     * @return The negotiated compression method for server to client communication
     */
    @Override
    public CompressionMethod getCompressionMethodServerToClient() {
        return context.getCompressionMethodServerToClient()
                .orElseGet(
                        () -> {
                            CompressionMethod negotiatedMethod =
                                    AlgorithmPicker.pickAlgorithm(
                                                    this
                                                            .getClientSupportedCompressionMethodsServerToClient(),
                                                    this
                                                            .getServerSupportedCompressionMethodsServerToClient())
                                            .orElse(
                                                    context.isClient()
                                                            ? this
                                                                    .getClientSupportedCompressionMethodsServerToClient()
                                                                    .get(0)
                                                            : this
                                                                    .getServerSupportedCompressionMethodsServerToClient()
                                                                    .get(0));
                            context.setCompressionMethodServerToClient(negotiatedMethod);
                            return negotiatedMethod;
                        });
    }
    // endregion

    // region Key Exchange
    /**
     * Retrieve the DH key exchange object from context. If no DH key exchange is available, a new
     * DH key exchange object will be constructed using the negotiated key exchange algorithm and
     * the context will be updated accordingly.
     *
     * @return The DH key exchange instance for named DH present in context
     */
    @Override
    public DhKeyExchange getDhKeyExchange() {
        return context.getDhKeyExchangeInstance()
                .orElseGet(
                        () -> {
                            KeyExchangeAlgorithm negotiatedAlgorithm =
                                    this.getKeyExchangeAlgorithm();
                            DhKeyExchange freshKeyExchange =
                                    DhKeyExchange.newInstance(context, negotiatedAlgorithm);
                            context.setDhKeyExchangeInstance(freshKeyExchange);
                            return freshKeyExchange;
                        });
    }

    /**
     * Retrieve the DH GEX (group exchange) key exchange object from context. If no DH GEX key
     * exchange is available, a new DH key exchange object will be constructed using the negotiated
     * key exchange algorithm and the context will be updated accordingly.
     *
     * @return The DH key exchange instance for group exchange present in context
     */
    @Override
    public DhKeyExchange getDhGexKeyExchange() {
        return context.getDhGexKeyExchangeInstance()
                .orElseGet(
                        () -> {
                            KeyExchangeAlgorithm negotiatedAlgorithm =
                                    this.getKeyExchangeAlgorithm();
                            DhKeyExchange freshKeyExchange =
                                    DhKeyExchange.newInstance(context, negotiatedAlgorithm);
                            context.setDhGexKeyExchangeInstance(freshKeyExchange);
                            return freshKeyExchange;
                        });
    }

    /**
     * Retrieve the ECDH key exchange object from context. If no ECDH key exchange is available, a
     * new ECDH key exchange object will be constructed using the negotiated key exchange algorithm
     * and the context will be updated accordingly.
     *
     * @return The ECDH key exchange instance present in context
     */
    @Override
    public AbstractEcdhKeyExchange getEcdhKeyExchange() {
        return context.getEcdhKeyExchangeInstance()
                .orElseGet(
                        () -> {
                            KeyExchangeAlgorithm negotiatedAlgorithm =
                                    this.getKeyExchangeAlgorithm();
                            AbstractEcdhKeyExchange freshKeyExchange =
                                    AbstractEcdhKeyExchange.newInstance(
                                            context, negotiatedAlgorithm);
                            context.setEcdhKeyExchangeInstance(freshKeyExchange);
                            return freshKeyExchange;
                        });
    }

    /**
     * Retrieve the RSA key exchange object from context. If no RSA key exchange is available, a new
     * RSA key exchange object will be constructed using the negotiated key exchange algorithm and
     * the context will be updated accordingly.
     *
     * @return The RSA key exchange instance present in context
     */
    @Override
    public RsaKeyExchange getRsaKeyExchange() {
        return context.getRsaKeyExchangeInstance()
                .orElseGet(
                        () -> {
                            KeyExchangeAlgorithm negotiatedAlgorithm =
                                    this.getKeyExchangeAlgorithm();
                            RsaKeyExchange freshKeyExchange =
                                    RsaKeyExchange.newInstance(context, negotiatedAlgorithm);
                            // Set transient key to ensure its presence
                            freshKeyExchange.setTransientKey(
                                    config.getFallbackRsaTransientPublicKey());
                            context.setRsaKeyExchangeInstance(freshKeyExchange);
                            return freshKeyExchange;
                        });
    }

    /**
     * Pick and return the host key from config that is compatible with the negotiated host key
     * algorithm. If multiple host keys of the same type are present, the first key will be
     * returned. If no appropriate host key is configured, this method will return the first key in
     * the list of host keys as a fallback.
     *
     * @return A host key matching the host key algorithms' key format. If no such host key is
     *     configured, the first key in the list of host keys will be returned as fallback.
     */
    @Override
    public SshPublicKey<?, ?> getNegotiatedHostKey() {
        Optional<PublicKeyAlgorithm> negotiatedHostKeyAlgorithm = context.getHostKeyAlgorithm();
        SshPublicKey<?, ?> fallback = config.getHostKeys().get(0);
        if (negotiatedHostKeyAlgorithm.isEmpty()) {
            LOGGER.warn(
                    "No server host key algorithm was negotiated, defaulting to the first server host key ("
                            + fallback
                            + ")");
            return fallback;
        }
        // Find the first configured host key whose format matches the negotiated server host key
        // format
        return config.getHostKeys().stream()
                .filter(
                        hk ->
                                hk.getPublicKeyFormat()
                                        == negotiatedHostKeyAlgorithm.get().getKeyFormat())
                .findFirst()
                .orElseGet(
                        () -> {
                            LOGGER.warn(
                                    "No server host key matching the negotiated algorithm '"
                                            + "' was found in the config, defaulting to the first server host key ("
                                            + fallback
                                            + ")");
                            return fallback;
                        });
    }

    /**
     * Retrieves the minimal group size of the requested DH group during group exchange.
     *
     * @return The minimal acceptable DH group size in bits
     */
    @Override
    public Integer getMinimalDhGroupSize() {
        return context.getMinimalDhGroupSize().orElse(config.getDhGexMinimalGroupSize());
    }

    /**
     * Retrieves the preferred group size of the requested DH group during group exchange.
     *
     * @return The preferred size in bits of an acceptable DH group
     */
    @Override
    public Integer getPreferredDhGroupSize() {
        return context.getPreferredDhGroupSize().orElse(config.getDhGexPreferredGroupSize());
    }

    /**
     * Retrieves the maximal group size of the requested DH group during group exchange.
     *
     * @return The maximal acceptable DH group size in bits
     */
    @Override
    public Integer getMaximalDhGroupSize() {
        return context.getMaximalDhGroupSize().orElse(config.getDhGexMaximalGroupSize());
    }
    // endregion

    /**
     * Retrieves the primary authentication method from config. A context field for authentication
     * method does not yet exist as the authentication protocol is only implemented for SSH-Attacker
     * in client mode.
     *
     * @return The primary authentication method for the given protocol flow
     */
    @Override
    public AuthenticationMethod getAuthenticationMethod() {
        return config.getAuthenticationMethod();
    }
}
