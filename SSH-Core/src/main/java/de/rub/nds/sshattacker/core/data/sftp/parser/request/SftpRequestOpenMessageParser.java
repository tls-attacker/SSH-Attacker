/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestOpenMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestOpenMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Chooser chooser;

    public SftpRequestOpenMessageParser(byte[] array, Chooser chooser) {
        super(array);
        this.chooser = chooser;
    }

    public SftpRequestOpenMessageParser(byte[] array, int startPosition, Chooser chooser) {
        super(array, startPosition);
        this.chooser = chooser;
    }

    @Override
    public SftpRequestOpenMessage createMessage() {
        return new SftpRequestOpenMessage();
    }

    private void parsePFlags() {
        int pFlags = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setPFlags(pFlags);
        LOGGER.debug("PFlags: {}", pFlags);
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer(), chooser);
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parsePFlags();
        parseAttributes();
    }
}
