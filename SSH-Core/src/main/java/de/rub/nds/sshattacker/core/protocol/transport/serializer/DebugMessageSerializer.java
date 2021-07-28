/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugMessageSerializer extends MessageSerializer<DebugMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DebugMessageSerializer(DebugMessage msg) {
        super(msg);
    }

    private void serializeAlwaysDisplayed() {
        LOGGER.debug(
                "Always displayed: " + Converter.byteToBoolean(msg.getAlwaysDisplay().getValue()));
        appendByte(msg.getAlwaysDisplay().getValue());
    }

    private void serializeMessage() {
        LOGGER.debug("Message length: " + msg.getMessageLength().getValue());
        appendInt(msg.getMessageLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Message: " + msg.getMessage().getValue());
        appendString(msg.getMessage().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: " + msg.getLanguageTagLength().getValue());
        appendInt(msg.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Language tag: " + msg.getLanguageTag().getValue());
        appendString(msg.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        serializeAlwaysDisplayed();
        serializeMessage();
        serializeLanguageTag();
    }
}
