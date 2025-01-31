/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.NoFlowControlExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NoFlowControlExtensionSerializer
        extends AbstractExtensionSerializer<NoFlowControlExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeExtensionValue(NoFlowControlExtension object, SerializerStream output) {
        serializeChoice(object, output);
    }

    private static void serializeChoice(NoFlowControlExtension object, SerializerStream output) {
        Integer versionLength = object.getChoiceLength().getValue();
        LOGGER.debug("Choice length: {}", versionLength);
        output.appendInt(versionLength);
        String choice = object.getChoice().getValue();
        LOGGER.debug("Choice: {}", choice);
        output.appendString(choice, StandardCharsets.US_ASCII);
    }
}
