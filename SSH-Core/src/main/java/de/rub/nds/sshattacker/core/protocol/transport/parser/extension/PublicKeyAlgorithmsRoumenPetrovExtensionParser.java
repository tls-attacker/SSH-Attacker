/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PublicKeyAlgorithmsRoumenPetrovExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyAlgorithmsRoumenPetrovExtensionParser
        extends AbstractExtensionParser<PublicKeyAlgorithmsRoumenPetrovExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PublicKeyAlgorithmsRoumenPetrovExtensionParser(byte[] array) {
        super(array);
    }

    public PublicKeyAlgorithmsRoumenPetrovExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected PublicKeyAlgorithmsRoumenPetrovExtension createExtension() {
        return new PublicKeyAlgorithmsRoumenPetrovExtension();
    }

    @Override
    protected void parseExtensionValue() {
        parsePublicKeyAlgorithmsLength();
        parsePublicKeyAlgorithms();
    }

    private void parsePublicKeyAlgorithmsLength() {
        extension.setPublicKeyAlgorithmsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Public key algorithms length: {}",
                extension.getPublicKeyAlgorithmsLength().getValue());
    }

    private void parsePublicKeyAlgorithms() {
        extension.setPublicKeyAlgorithms(
                parseByteString(
                        extension.getPublicKeyAlgorithmsLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug("Public key algorithms: {}", extension.getPublicKeyAlgorithms().getValue());
    }
}
