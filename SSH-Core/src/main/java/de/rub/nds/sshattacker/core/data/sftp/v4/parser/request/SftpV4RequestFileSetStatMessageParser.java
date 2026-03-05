/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestWithHandleMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder.SftpV4FileAttributesParser;

public class SftpV4RequestFileSetStatMessageParser
        extends SftpRequestWithHandleMessageParser<SftpV4RequestFileSetStatMessage> {

    public SftpV4RequestFileSetStatMessageParser(byte[] array) {
        super(array);
    }

    public SftpV4RequestFileSetStatMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpV4RequestFileSetStatMessage createMessage() {
        return new SftpV4RequestFileSetStatMessage();
    }

    private void parseAttributes() {
        SftpV4FileAttributesParser attributesParser =
                new SftpV4FileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithHandleSpecificContents() {
        parseAttributes();
    }
}
