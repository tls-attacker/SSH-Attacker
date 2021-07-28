/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.DisconnectReason;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageParser extends MessageParser<DisconnectMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DisconnectMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseReasonCode(DisconnectMessage msg) {
        msg.setReasonCode(parseIntField(DataFormatConstants.INT32_SIZE));
        LOGGER.debug(
                "Reason: "
                        + DisconnectReason.fromId(msg.getReasonCode().getValue()).toString()
                        + " (Code: "
                        + msg.getReasonCode().getValue()
                        + ")");
    }

    private void parseDescription(DisconnectMessage msg) {
        msg.setDescriptionLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Description length: " + msg.getDescriptionLength().getValue());
        msg.setDescription(
                parseByteString(msg.getDescriptionLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Description: " + msg.getDescription().getValue());
    }

    private void parseLanguageTag(DisconnectMessage msg) {
        msg.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Language tag length: " + msg.getLanguageTagLength().getValue());
        msg.setLanguageTag(
                parseByteString(msg.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Language tag: " + msg.getLanguageTag().getValue());
    }

    @Override
    protected void parseMessageSpecificPayload(DisconnectMessage msg) {
        parseReasonCode(msg);
        parseDescription(msg);
        parseLanguageTag(msg);
    }

    @Override
    public DisconnectMessage createMessage() {
        return new DisconnectMessage();
    }
}
