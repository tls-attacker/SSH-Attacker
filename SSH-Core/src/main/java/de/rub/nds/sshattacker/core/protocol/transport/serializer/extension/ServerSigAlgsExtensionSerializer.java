/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSigAlgsExtensionSerializer
        extends AbstractExtensionSerializer<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeExtensionValue(ServerSigAlgsExtension object, SerializerStream output) {
        serializeAcceptedPublicKeyAlgorithmsLength(object, output);
        serializeAcceptedPublicKeyAlgorithms(object, output);
    }

    private static void serializeAcceptedPublicKeyAlgorithmsLength(
            ServerSigAlgsExtension object, SerializerStream output) {
        Integer acceptedPublicKeyAlgorithmsLength =
                object.getAcceptedPublicKeyAlgorithmsLength().getValue();
        LOGGER.debug(
                "Accepted public key algorithms length: {}", acceptedPublicKeyAlgorithmsLength);
        output.appendInt(acceptedPublicKeyAlgorithmsLength);
    }

    private static void serializeAcceptedPublicKeyAlgorithms(
            ServerSigAlgsExtension object, SerializerStream output) {
        String acceptedPublicKeyAlgorithms = object.getAcceptedPublicKeyAlgorithms().getValue();
        LOGGER.debug(
                "Accepted public key algorithms: {}",
                () -> backslashEscapeString(acceptedPublicKeyAlgorithms));
        output.appendString(acceptedPublicKeyAlgorithms, StandardCharsets.US_ASCII);
    }
}
