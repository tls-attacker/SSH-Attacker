/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.constants.CompressionMethod;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.DelayCompressionExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.DelayCompressionExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.DelayCompressionExtensionSerializer;
import de.rub.nds.sshattacker.core.protocol.util.AlgorithmPicker;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DelayCompressionExtensionHandler
        extends AbstractExtensionHandler<DelayCompressionExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DelayCompressionExtensionHandler(SshContext context) {
        super(context);
    }

    public DelayCompressionExtensionHandler(
            SshContext context, DelayCompressionExtension extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        if (context.isHandleAsClient()) {
            context.setServerSupportedDelayCompressionMethods(
                    Converter.nameListToEnumValues(
                            extension.getCompressionMethodsServerToClient().getValue(),
                            CompressionMethod.class));
        } else {
            context.setClientSupportedDelayCompressionMethods(
                    Converter.nameListToEnumValues(
                            extension.getCompressionMethodsClientToServer().getValue(),
                            CompressionMethod.class));
        }
        // get client supported compression methods
        List<CompressionMethod> clientSupportedCompressionMethods =
                context.getChooser().getClientSupportedDelayCompressionMethods();
        // get server supported compression methods
        List<CompressionMethod> serverSupportedCompressionMethods =
                context.getChooser().getServerSupportedDelayCompressionMethods();
        // determine common compression method
        CompressionMethod commonCompressionMethod =
                getCommonCompressionMethod(
                        clientSupportedCompressionMethods, serverSupportedCompressionMethods);
        // set in context
        context.setSelectedDelayCompressionMethod(commonCompressionMethod);
        context.setDelayCompressionExtensionReceived(true);
    }

    @Override
    public DelayCompressionExtensionParser getParser(byte[] array) {
        return new DelayCompressionExtensionParser(array);
    }

    @Override
    public DelayCompressionExtensionParser getParser(byte[] array, int startPosition) {
        return new DelayCompressionExtensionParser(array, startPosition);
    }

    @Override
    public DelayCompressionExtensionPreparator getPreparator() {
        return new DelayCompressionExtensionPreparator(context.getChooser(), extension);
    }

    @Override
    public DelayCompressionExtensionSerializer getSerializer() {
        return new DelayCompressionExtensionSerializer(extension);
    }

    private CompressionMethod getCommonCompressionMethod(
            List<CompressionMethod> clientSupportedCompressionMethods,
            List<CompressionMethod> serverSupportedCompressionMethods) {
        Optional<CompressionMethod> commonCompressionMethod =
                AlgorithmPicker.pickAlgorithm(
                        clientSupportedCompressionMethods, serverSupportedCompressionMethods);
        if (commonCompressionMethod.isPresent()) {
            return commonCompressionMethod.get();
        } else {
            LOGGER.warn("No common compression method found from delay-compression extension!");
            context.setDelayCompressionExtensionNegotiationFailed(true);
            return null;
        }
    }
}
