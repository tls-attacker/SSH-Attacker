/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PublicKeyAlgorithmsRoumenPetrovExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.PublicKeyAlgorithmsRoumenPetrovExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.PublicKeyAlgorithmsRoumenPetrovExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.PublicKeyAlgorithmsRoumenPetrovExtensionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyAlgorithmsRoumenPetrovExtensionHandler
        extends AbstractExtensionHandler<PublicKeyAlgorithmsRoumenPetrovExtension> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    public PublicKeyAlgorithmsRoumenPetrovExtensionHandler(
            SshContext context, PublicKeyAlgorithmsRoumenPetrovExtension extension) {
        super(context, extension);
        this.context = context;
    }

    @Override
    public void adjustContext() {
        String acceptedAlgorithms = this.extension.getAcceptedPublicKeyAlgorithms().getValue();

        if (acceptedAlgorithms != null) {
            LOGGER.debug(
                    "Accepted Public-Key-Algorithms (Roumen Petrov Extension): {}",
                    acceptedAlgorithms);
            context.setSupportedPublicKeyAlgorithms(acceptedAlgorithms);
        } else {
            LOGGER.warn("No accepted Public-Key-Algorithms in the Roumen Petrov extension found.");
        }
    }

    @Override
    public PublicKeyAlgorithmsRoumenPetrovExtensionParser getParser(byte[] array) {
        return new PublicKeyAlgorithmsRoumenPetrovExtensionParser(array, 0);
    }

    @Override
    public PublicKeyAlgorithmsRoumenPetrovExtensionParser getParser(
            byte[] array, int startPosition) {
        return new PublicKeyAlgorithmsRoumenPetrovExtensionParser(array, startPosition);
    }

    @Override
    public Preparator<PublicKeyAlgorithmsRoumenPetrovExtension> getPreparator() {
        return new PublicKeyAlgorithmsRoumenPetrovExtensionPreparator(
                context.getChooser(), extension);
    }

    @Override
    public Serializer<PublicKeyAlgorithmsRoumenPetrovExtension> getSerializer() {
        return new PublicKeyAlgorithmsRoumenPetrovExtensionSerializer(extension);
    }
}
