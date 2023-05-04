/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.ServerSigAlgsExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.ServerSigAlgsExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.ServerSigAlgsExtensionSerializer;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
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
            context.setServerSupportedPublicKeyAlgorithmsForAuthentification(
                    Converter.nameListToEnumValues(
                            extension.getAcceptedPublicKeyAlgorithms().getValue(),
                            PublicKeyFormat.class));

            List<PublicKeyFormat> clientSupportedPublicKeyAlgorithms =
                    collectSupportedPublicKeyAlgorithmsFromClient(
                            context.getConfig().getUserKeys());

            List<PublicKeyFormat> serverSupportedPublicKeyAlgorithms =
                    context.getChooser().getServerSupportedPublicKeyAlgorithmsForAuthentification();

            // pick common algorithm
            Optional<PublicKeyFormat> commonAlgorithm =
                    AlgorithmPicker.pickAlgorithm(
                            clientSupportedPublicKeyAlgorithms, serverSupportedPublicKeyAlgorithms);

            // transform common algorithm into SshKey<?, ?> and set in context
            SshPublicKey<?, ?> selectedAlgorithm =
                    getSshPublicKeyFromSelectedPublicKeyAlgorithm(commonAlgorithm.orElse(null));
            context.setSelectedPublicKeyAlgorithmForAuthentification(selectedAlgorithm);
        }
        // receiving "server-sig-algs" extension as a server -> ignore "server-sig-algs"
        else {
            LOGGER.warn(
                    "Client sent ServerSigAlgsExtension which is supposed to be sent by the server only!");
        }
    }

    private SshPublicKey<?, ?> getSshPublicKeyFromSelectedPublicKeyAlgorithm(
            PublicKeyFormat algorithm) {
        // SshPublicKey for ssh-dss if no match was found
        // ssh-dss is REQUIRED to be implemented by every server(RFC 4253 Section 6.6)
        SshPublicKey<?, ?> defaultKey = null;
        boolean noCommonAlgorithmFound = (algorithm == null);

        for (SshPublicKey<?, ?> key : context.getConfig().getUserKeys()) {
            PublicKeyFormat publicKeyFormat = key.getPublicKeyFormat();
            if (publicKeyFormat.equals(algorithm)) {
                return key;
            }
            if (noCommonAlgorithmFound && publicKeyFormat.equals(PublicKeyFormat.SSH_DSS)) {
                defaultKey = key;
                break;
            }
        }
        LOGGER.warn(
                "No intersection of public key algorithms for client authentification found!\n"
                        + "Using ssh-dss as public key algorithm for authentification!");
        return defaultKey;
    }

    // extract all public key algorithms supported by the client from the List of user keys
    // and return as List<PublicKeyFormat>
    private List<PublicKeyFormat> collectSupportedPublicKeyAlgorithmsFromClient(
            List<SshPublicKey<?, ?>> keys) {
        List<PublicKeyFormat> algorithms = new LinkedList<>();
        for (SshPublicKey<?, ?> key : keys) {
            algorithms.add(key.getPublicKeyFormat());
        }
        return algorithms;
    }
}
