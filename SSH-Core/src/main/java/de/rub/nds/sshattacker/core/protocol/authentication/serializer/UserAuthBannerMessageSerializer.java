/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthBannerMessageSerializer extends MessageSerializer<UserAuthBannerMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthBannerMessageSerializer(UserAuthBannerMessage msg) {
        super(msg);
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
        serializeMessage();
        serializeLanguageTag();
    }
}
