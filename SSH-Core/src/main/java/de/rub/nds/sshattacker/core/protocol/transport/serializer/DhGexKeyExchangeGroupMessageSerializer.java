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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeGroupMessageSerializer(DhGexKeyExchangeGroupMessage message) {
        super(message);
    }

    private void serializeGroupModulus() {
        appendInt(
                message.getGroupModulusLength().getValue(), DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Group modulus length: " + message.getGroupModulusLength().getValue());
        appendBytes(message.getGroupModulus().getValue().toByteArray());
        LOGGER.debug(
                "Group modulus: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getGroupModulus().getValue().toByteArray()));
    }

    private void serializeGroupGenerator() {
        appendInt(
                message.getGroupGeneratorLength().getValue(),
                DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Group generator length: " + message.getGroupGeneratorLength().getValue());
        appendBytes(message.getGroupGenerator().getValue().toByteArray());
        LOGGER.debug(
                "Group generator: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getGroupGenerator().getValue().toByteArray()));
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeGroupModulus();
        serializeGroupGenerator();
    }

}
