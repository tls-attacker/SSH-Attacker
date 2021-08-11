/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import java.nio.charset.StandardCharsets;

public class UserAuthBannerMessageParser extends MessageParser<UserAuthBannerMessage> {

    public UserAuthBannerMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    @Override
    public UserAuthBannerMessage createMessage() {
        return new UserAuthBannerMessage();
    }

    private void parseMessage(UserAuthBannerMessage msg) {
        msg.setMessageLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        msg.setMessage(
                parseByteString(msg.getMessageLength().getValue(), StandardCharsets.UTF_8), false);
    }

    private void parseLanguageTag(UserAuthBannerMessage msg) {
        msg.setLanguageTagLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        msg.setLanguageTag(
                parseByteString(msg.getLanguageTagLength().getValue(), StandardCharsets.US_ASCII),
                false);
    }

    @Override
    protected void parseMessageSpecificPayload(UserAuthBannerMessage msg) {
        parseMessage(msg);
        parseLanguageTag(msg);
    }
}
