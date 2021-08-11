/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageSerializer extends MessageSerializer<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageSerializer(DisconnectMessage msg) {
        super(msg);
    }

    private void serializeReasonCode() {
        LOGGER.debug(
                "Reason: "
                        + DisconnectReason.fromId(msg.getReasonCode().getValue())
                        + " (Code: "
                        + msg.getReasonCode().getValue()
                        + ")");
        appendInt(msg.getReasonCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeDescription() {
        LOGGER.debug("Description length: " + msg.getDescriptionLength().getValue());
        appendInt(msg.getDescriptionLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Description: " + msg.getDescription().getValue());
        appendString(msg.getDescription().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: " + msg.getLanguageTagLength().getValue());
        appendInt(msg.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Language tag: " + msg.getLanguageTag().getValue());
        appendString(msg.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeReasonCode();
        serializeDescription();
        serializeLanguageTag();
    }
}
