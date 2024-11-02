/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_response;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseCheckFileMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseMessageParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseCheckFileMessageParser
        extends SftpResponseMessageParser<SftpResponseCheckFileMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseCheckFileMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseCheckFileMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseCheckFileMessage createMessage() {
        return new SftpResponseCheckFileMessage();
    }

    private void parseUsedHashAlgorithm() {
        message.setUsedHashAlgorithmLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "UsedHashAlgorithm length: {}", message.getUsedHashAlgorithmLength().getValue());
        message.setUsedHashAlgorithm(
                parseByteString(
                        message.getUsedHashAlgorithmLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "UsedHashAlgorithm: {}",
                () -> backslashEscapeString(message.getUsedHashAlgorithm().getValue()));
    }

    private void parseHash() {
        message.setHash(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Hash: {}", () -> ArrayConverter.bytesToRawHexString(message.getHash().getValue()));
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseUsedHashAlgorithm();
        parseHash();
    }
}
