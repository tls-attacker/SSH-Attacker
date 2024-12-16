/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPkOkMessageParser extends SshMessageParser<UserAuthPkOkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPkOkMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthPkOkMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected UserAuthPkOkMessage createMessage() {
        return new UserAuthPkOkMessage();
    }

    private void parsePubkey() {
        int pubkeyLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setPubkeyLength(pubkeyLength);
        LOGGER.debug("Pubkey length: {}", pubkeyLength);
        byte[] pubkey = parseByteArrayField(pubkeyLength);
        message.setPubkey(pubkey);
        LOGGER.debug("Pubkey: {}", () -> ArrayConverter.bytesToRawHexString(pubkey));
    }

    private void parsePubkeyAlgName() {
        int pubkeyAlgNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setPubkeyAlgNameLength(pubkeyAlgNameLength);
        LOGGER.debug("Pubkey algorithm name length: {}", pubkeyAlgNameLength);
        String pubkeyAlgName = parseByteString(pubkeyAlgNameLength, StandardCharsets.US_ASCII);
        message.setPubkeyAlgName(pubkeyAlgName);
        LOGGER.debug("Pubkey algorithm name: {}", () -> backslashEscapeString(pubkeyAlgName));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePubkeyAlgName();
        parsePubkey();
    }
}
