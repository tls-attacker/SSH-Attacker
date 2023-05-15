/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

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

    @Override
    protected void parseExtensionValue() {
        parseAcceptedPublicKeyAlgorithmsLength();
        parseAcceptedPublicKeyAlgorithms();
    }

    private void parseAcceptedPublicKeyAlgorithmsLength() {
        extension.setAcceptedPublicKeyAlgorithmsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Accepted public key algorithms length: {}",
                extension.getAcceptedPublicKeyAlgorithmsLength().getValue());
    }

    private void parseAcceptedPublicKeyAlgorithms() {
        extension.setAcceptedPublicKeyAlgorithms(
                parseByteString(
                        extension.getAcceptedPublicKeyAlgorithmsLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Accepted public key algorithms: {}",
                extension.getAcceptedPublicKeyAlgorithms().getValue());
    }
}
