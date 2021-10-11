/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageSerializer
        extends MessageSerializer<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeGroupMessageSerializer(DhGexKeyExchangeGroupMessage msg) {
        super(msg);
    }

    private void serializeGroupModulus(DhGexKeyExchangeGroupMessage msg) {
        appendInt(msg.getGroupModulusLength().getValue(), DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Group modulus length: " + msg.getGroupModulusLength().getValue());
        appendBytes(msg.getGroupModulus().getValue().toByteArray());
        LOGGER.debug(
                "Group modulus: "
                        + ArrayConverter.bytesToRawHexString(
                                msg.getGroupModulus().getValue().toByteArray()));
    }

    private void serializeGroupGenerator(DhGexKeyExchangeGroupMessage msg) {
        appendInt(msg.getGroupGeneratorLength().getValue(), DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Group generator length: " + msg.getGroupGeneratorLength().getValue());
        appendBytes(msg.getGroupGenerator().getValue().toByteArray());
        LOGGER.debug(
                "Group generator: "
                        + ArrayConverter.bytesToRawHexString(
                                msg.getGroupGenerator().getValue().toByteArray()));
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeGroupModulus(msg);
        serializeGroupGenerator(msg);
    }
}
