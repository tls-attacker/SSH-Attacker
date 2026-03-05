/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSigAlgsExtensionParser extends AbstractExtensionParser<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerSigAlgsExtensionParser(byte[] array) {
        super(array);
    }

    public ServerSigAlgsExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected ServerSigAlgsExtension createExtension() {
        return new ServerSigAlgsExtension();
    }

    private void parseAcceptedPublicKeyAlgorithms() {
        int acceptedPublicKeyAlgorithmsLength = parseIntField();
        extension.setAcceptedPublicKeyAlgorithmsLength(acceptedPublicKeyAlgorithmsLength);
        LOGGER.debug(
                "Accepted public key algorithms length: {}", acceptedPublicKeyAlgorithmsLength);
        String acceptedPublicKeyAlgorithms =
                parseByteString(acceptedPublicKeyAlgorithmsLength, StandardCharsets.US_ASCII);
        extension.setAcceptedPublicKeyAlgorithms(acceptedPublicKeyAlgorithms);
        LOGGER.debug("Accepted public key algorithms: {}", acceptedPublicKeyAlgorithms);
    }

    @Override
    protected void parseExtensionValue() {
        parseAcceptedPublicKeyAlgorithms();
    }
}
