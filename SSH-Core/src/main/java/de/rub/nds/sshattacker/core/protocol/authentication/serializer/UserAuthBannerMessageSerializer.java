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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthBannerMessageSerializer extends SshMessageSerializer<UserAuthBannerMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthBannerMessageSerializer(UserAuthBannerMessage message) {
        super(message);
    }

    private void serializeMessage() {
        LOGGER.debug("Message length: " + message.getMessageLength().getValue());
        appendInt(message.getMessageLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Message: " + message.getMessage().getValue());
        appendString(message.getMessage().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeLanguageTag() {
        LOGGER.debug("Language tag length: " + message.getLanguageTagLength().getValue());
        appendInt(
                message.getLanguageTagLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Language tag: " + message.getLanguageTag().getValue());
        appendString(message.getLanguageTag().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeMessage();
        serializeLanguageTag();
    }
}
