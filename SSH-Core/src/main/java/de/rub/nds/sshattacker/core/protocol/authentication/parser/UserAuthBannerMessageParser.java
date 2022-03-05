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
import java.nio.charset.StandardCharsets;

public class UserAuthBannerMessageParser extends SshMessageParser<UserAuthBannerMessage> {

    public UserAuthBannerMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthBannerMessage createMessage() {
        return new UserAuthBannerMessage();
    }

    private void parseMessage() {
        message.setMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        message.setMessage(
                parseByteString(message.getMessageLength().getValue(), StandardCharsets.UTF_8),
                false);
    }

    private void parseLanguageTag() {
        message.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        message.setLanguageTag(
                parseByteString(
                        message.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII),
                false);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseMessage();
        parseLanguageTag();
    }
}
