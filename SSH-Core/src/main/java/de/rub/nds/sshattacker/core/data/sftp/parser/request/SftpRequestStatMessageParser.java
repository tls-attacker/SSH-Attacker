/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestStatMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestStatMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestStatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Chooser chooser;

    public SftpRequestStatMessageParser(byte[] array, Chooser chooser) {
        super(array);
        this.chooser = chooser;
    }

    public SftpRequestStatMessageParser(byte[] array, int startPosition, Chooser chooser) {
        super(array, startPosition);
        this.chooser = chooser;
    }

    @Override
    public SftpRequestStatMessage createMessage() {
        return new SftpRequestStatMessage();
    }

    private void parseFlags() {
        if (chooser.getSftpNegotiatedVersion() > 3) {
            int flags = parseIntField(DataFormatConstants.UINT32_SIZE);
            message.setFlags(flags);
            LOGGER.debug("Flags: {}", flags);
        }
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseFlags();
    }
}
