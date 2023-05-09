/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.ServerSigAlgsExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.ServerSigAlgsExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.ServerSigAlgsExtensionSerializer;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSigAlgsExtensionHandler
        extends AbstractExtensionHandler<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerSigAlgsExtensionHandler(SshContext context) {
        super(context);
    }

    public ServerSigAlgsExtensionHandler(SshContext context, ServerSigAlgsExtension extension) {
        super(context, extension);
    }

    @Override
    public ServerSigAlgsExtensionParser getParser(byte[] array) {
        return new ServerSigAlgsExtensionParser(array);
    }

    @Override
    public ServerSigAlgsExtensionParser getParser(byte[] array, int startPosition) {
        return new ServerSigAlgsExtensionParser(array, startPosition);
    }

    @Override
    public ServerSigAlgsExtensionPreparator getPreparator() {
        return new ServerSigAlgsExtensionPreparator(context.getChooser(), extension);
    }

    @Override
    public ServerSigAlgsExtensionSerializer getSerializer() {
        return new ServerSigAlgsExtensionSerializer(extension);
    }

    @Override
    public void adjustContext() {
        // receiving "server-sig-algs" extension as a client -> context has to be updated
        if (context.isHandleAsClient()) {
            context.setServerSupportedPublicKeyAlgorithmsForAuthentication(
                    Converter.nameListToEnumValues(
                            extension.getAcceptedPublicKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));

            // get client supported public key algorithms
            List<PublicKeyAlgorithm> clientSupportedPublicKeyAlgorithms =
                    this.collectClientSupportedPublicKeyAlgorithms();
            // get server supported public key algorithms
            List<PublicKeyAlgorithm> serverSupportedPublicKeyAlgorithms =
                    context.getServerSupportedPublicKeyAlgorithmsForAuthentication().orElse(null);
            // determine intersection
            PublicKeyAlgorithm commonAlgorithm =
                    this.getCommonPublicKeyAlgorithm(
                            clientSupportedPublicKeyAlgorithms, serverSupportedPublicKeyAlgorithms);
            // get SshPublicKey of selected public key algorithm
            SshPublicKey<?, ?> publicKey = this.getSelectedPublicKeyFromAlgorithm(commonAlgorithm);
            // set in context
            context.setSelectedPublicKeyForAuthentication(publicKey);
        }
        // receiving "server-sig-algs" extension as a server -> ignore "server-sig-algs"
        else {
            LOGGER.warn(
                    "Client sent ServerSigAlgsExtension which is supposed to be sent by the server only!");
        }
    }

    private List<PublicKeyAlgorithm> collectClientSupportedPublicKeyAlgorithms() {
        return context.getConfig().getUserKeys().stream()
                .map(
                        algorithm ->
                                PublicKeyAlgorithm.fromName(
                                        algorithm.getPublicKeyFormat().getName()))
                .collect(Collectors.toList());
    }

    private PublicKeyAlgorithm getCommonPublicKeyAlgorithm(
            List<PublicKeyAlgorithm> clientSupportedPublicKeyAlgorithms,
            List<PublicKeyAlgorithm> serverSupportedPublicKeyAlgorithms) {
        if (clientSupportedPublicKeyAlgorithms == null
                || serverSupportedPublicKeyAlgorithms == null) {
            // use ssh-dss as default which is REQUIRED to be implemented by every server
            // (RFC 4253 Section 6.6)
            return PublicKeyAlgorithm.SSH_DSS;
        }
        Optional<PublicKeyAlgorithm> commonAlgorithm =
                AlgorithmPicker.pickAlgorithm(
                        clientSupportedPublicKeyAlgorithms, serverSupportedPublicKeyAlgorithms);
        if (commonAlgorithm.isPresent()) {
            return commonAlgorithm.get();
        } else {
            LOGGER.warn(
                    "No common public key algorithm found from server-sig-algs extension! "
                            + "Using ssh-dss as public key algorithm for authentication!");
            return PublicKeyAlgorithm.SSH_DSS;
        }
    }

    private SshPublicKey<?, ?> getSelectedPublicKeyFromAlgorithm(
            PublicKeyAlgorithm publicKeyAlgorithm) {
        List<SshPublicKey<?, ?>> keys =
                context.getConfig().getUserKeys().stream()
                        .filter(
                                algorithm ->
                                        PublicKeyAlgorithm.fromName(
                                                        algorithm.getPublicKeyFormat().getName())
                                                .equals(publicKeyAlgorithm))
                        .collect(Collectors.toList());
        if (keys.size() == 0) {
            // no match -> use ssh-dss as default which is REQUIRED to be implemented by every
            // server
            // (RFC 4253 Section 6.6)
            return context.getConfig().getUserKeys().stream()
                    .filter(
                            algorithm ->
                                    PublicKeyAlgorithm.fromName(
                                                    algorithm.getPublicKeyFormat().getName())
                                            .equals(PublicKeyAlgorithm.SSH_DSS))
                    .collect(Collectors.toList())
                    .get(0);
        }
        return keys.get(0);
    }
}
