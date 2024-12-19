/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PublicKeyAlgorithmsRoumenPetrovExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyAlgorithmsRoumenPetrovExtensionSerializer
        extends AbstractExtensionSerializer<PublicKeyAlgorithmsRoumenPetrovExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PublicKeyAlgorithmsRoumenPetrovExtensionSerializer(
            PublicKeyAlgorithmsRoumenPetrovExtension extension) {
        super(extension);
    }

    @Override
    protected void serializeExtensionValue() {
        serializePublicKeyAlgorithmsLength();
        serializePublicKeyAlgorithms();
    }

    private void serializePublicKeyAlgorithmsLength() {
        Integer publicKeyAlgorithmsLength = extension.getPublicKeyAlgorithmsLength().getValue();
        LOGGER.debug("Public key algorithms length: {}", publicKeyAlgorithmsLength);
        appendInt(publicKeyAlgorithmsLength, DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializePublicKeyAlgorithms() {
        LOGGER.debug("Public key algorithms: {}", extension.getPublicKeyAlgorithms().getValue());
        appendString(extension.getPublicKeyAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }
}
