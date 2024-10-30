/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestOpenMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpFileAttributesParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestOpenMessageParser extends SftpRequestMessageParser<SftpRequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestOpenMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestOpenMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestOpenMessage createMessage() {
        return new SftpRequestOpenMessage();
    }

    private void parseFilename() {
        message.setFilenameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Filename length: {}", message.getFilenameLength().getValue());
        message.setFilename(
                parseByteString(message.getFilenameLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Filename: {}", () -> backslashEscapeString(message.getFilename().getValue()));
    }

    private void parsePFlags() {
        message.setPFlags(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("PFlags: {}", message.getPFlags().getValue());
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestSpecificContents() {
        parseFilename();
        parsePFlags();
        parseAttributes();
    }
}
