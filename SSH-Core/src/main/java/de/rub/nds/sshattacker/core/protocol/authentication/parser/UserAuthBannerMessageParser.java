/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthBannerMessageParser extends SshMessageParser<UserAuthBannerMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*    public UserAuthBannerMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthBannerMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    public UserAuthBannerMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(UserAuthBannerMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        // parseData(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    private void parseData(UserAuthBannerMessage msg) {
        msg.setMessage(parseByteArrayField(getBytesLeft()));
        LOGGER.debug("Data: {}", msg.getMessage().getValue());
    }

    /*
        @Override
        public UserAuthBannerMessage createMessage() {
            return new UserAuthBannerMessage();
        }
    */

    private void parseMessage(UserAuthBannerMessage message) {
        message.setMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        message.setMessage(
                parseByteString(message.getMessageLength().getValue(), StandardCharsets.UTF_8),
                false);
    }

    private void parseLanguageTag(UserAuthBannerMessage message) {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII),
                false);
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthBannerMessage message) {
        parseMessage(message);
        parseLanguageTag(message);
    }
}
