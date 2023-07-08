/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPkOkMessageParser extends SshMessageParser<UserAuthPkOkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public UserAuthPkOkMessageParser(byte[] array) {
            super(array);
        }
        public UserAuthPkOkMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public UserAuthPkOkMessageParser(InputStream stream) {
        super(stream);
    }

    /*
        @Override
        protected UserAuthPkOkMessage createMessage() {
            return new UserAuthPkOkMessage();
        }
    */

    @Override
    public void parse(UserAuthPkOkMessage message) {
        LOGGER.debug("Parsing UserAuthBannerMessage");
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    private void parsePubkey(UserAuthPkOkMessage message) {
        message.setPubkeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Pubkey length: " + message.getPubkeyLength().getValue());
        message.setPubkey(
                parseByteString(message.getPubkeyLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Pubkey: {}", backslashEscapeString(message.getPubkey().getValue()));
    }

    private void parsePubkeyAlgName(UserAuthPkOkMessage message) {
        message.setPubkeyAlgNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Pubkey algorithm name length: " + message.getPubkeyAlgNameLength().getValue());
        message.setPubkeyAlgName(
                parseByteString(
                        message.getPubkeyAlgNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Pubkey algorithm name: {}",
                backslashEscapeString(message.getPubkeyAlgName().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(UserAuthPkOkMessage message) {
        parsePubkeyAlgName(message);
        parsePubkey(message);
    }
}
