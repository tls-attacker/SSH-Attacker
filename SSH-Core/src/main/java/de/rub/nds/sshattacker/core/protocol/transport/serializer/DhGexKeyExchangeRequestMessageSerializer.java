/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeMinimalGroupSize(
            DhGexKeyExchangeRequestMessage object, SerializerStream output) {
        Integer minimalGroupSize = object.getMinimalGroupSize().getValue();
        LOGGER.debug("Minimal group size: {}", minimalGroupSize);
        output.appendInt(minimalGroupSize);
    }

    private static void serializePreferredGroupSize(
            DhGexKeyExchangeRequestMessage object, SerializerStream output) {
        Integer preferredGroupSize = object.getPreferredGroupSize().getValue();
        LOGGER.debug("Preferred group size: {}", preferredGroupSize);
        output.appendInt(preferredGroupSize);
    }

    private static void serializeMaximalGroupSize(
            DhGexKeyExchangeRequestMessage object, SerializerStream output) {
        Integer maximalGroupSize = object.getMaximalGroupSize().getValue();
        LOGGER.debug("Maximal group size: {}", maximalGroupSize);
        output.appendInt(maximalGroupSize);
    }

    @Override
    protected void serializeMessageSpecificContents(
            DhGexKeyExchangeRequestMessage object, SerializerStream output) {
        serializeMinimalGroupSize(object, output);
        serializePreferredGroupSize(object, output);
        serializeMaximalGroupSize(object, output);
    }
}
