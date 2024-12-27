/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeGroupModulus(
            DhGexKeyExchangeGroupMessage object, SerializerStream output) {
        Integer groupModulusLength = object.getGroupModulusLength().getValue();
        LOGGER.debug("Group modulus length: {}", groupModulusLength);
        output.appendInt(groupModulusLength, DataFormatConstants.MPINT_SIZE_LENGTH);
        output.appendBytes(object.getGroupModulus().getValue().toByteArray());
        LOGGER.debug(
                "Group modulus: {}",
                () ->
                        ArrayConverter.bytesToRawHexString(
                                object.getGroupModulus().getValue().toByteArray()));
    }

    private static void serializeGroupGenerator(
            DhGexKeyExchangeGroupMessage object, SerializerStream output) {
        Integer groupGeneratorLength = object.getGroupGeneratorLength().getValue();
        LOGGER.debug("Group generator length: {}", groupGeneratorLength);
        output.appendInt(groupGeneratorLength, DataFormatConstants.MPINT_SIZE_LENGTH);
        output.appendBytes(object.getGroupGenerator().getValue().toByteArray());
        LOGGER.debug(
                "Group generator: {}",
                () ->
                        ArrayConverter.bytesToRawHexString(
                                object.getGroupGenerator().getValue().toByteArray()));
    }

    @Override
    protected void serializeMessageSpecificContents(
            DhGexKeyExchangeGroupMessage object, SerializerStream output) {
        serializeGroupModulus(object, output);
        serializeGroupGenerator(object, output);
    }
}
