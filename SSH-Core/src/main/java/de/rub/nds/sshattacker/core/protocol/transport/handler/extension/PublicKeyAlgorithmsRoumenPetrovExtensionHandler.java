/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

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

    public PublicKeyAlgorithmsRoumenPetrovExtensionHandler(
            SshContext context, PublicKeyAlgorithmsRoumenPetrovExtension extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        String acceptedAlgorithms = extension.getPublicKeyAlgorithms().getValue();

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
        return new PublicKeyAlgorithmsRoumenPetrovExtensionParser(array);
    }

    @Override
    public PublicKeyAlgorithmsRoumenPetrovExtensionParser getParser(
            byte[] array, int startPosition) {
        return new PublicKeyAlgorithmsRoumenPetrovExtensionParser(array, startPosition);
    }

    public static final PublicKeyAlgorithmsRoumenPetrovExtensionPreparator PREPARATOR =
            new PublicKeyAlgorithmsRoumenPetrovExtensionPreparator();

    public static final PublicKeyAlgorithmsRoumenPetrovExtensionSerializer SERIALIZER =
            new PublicKeyAlgorithmsRoumenPetrovExtensionSerializer();
}
