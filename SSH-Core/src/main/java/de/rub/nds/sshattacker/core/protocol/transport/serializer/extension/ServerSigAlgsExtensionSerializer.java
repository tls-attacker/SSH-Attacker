/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ServerSigAlgsExtensionSerializer
        extends AbstractExtensionSerializer<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerSigAlgsExtensionSerializer(ServerSigAlgsExtension extension) {
        super(extension);
    }

    @Override
    protected void serializeExtensionValue() {
        this.serializeAcceptedPublicKeyAlgorithmsLength();
        this.serializeAcceptedPublicKeyAlgorithms();
    }

    private void serializeAcceptedPublicKeyAlgorithmsLength() {
        LOGGER.debug(
                "Accepted public key algorithms length: {}",
                extension.getAcceptedPublicKeyAlgorithmsLength().getValue());
        appendInt(
                extension.getAcceptedPublicKeyAlgorithmsLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeAcceptedPublicKeyAlgorithms() {
        LOGGER.debug(
                "Accepted public key algorithms: "
                        + extension.getAcceptedPublicKeyAlgorithms().getValue());
        appendString(
                extension.getAcceptedPublicKeyAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }
}
