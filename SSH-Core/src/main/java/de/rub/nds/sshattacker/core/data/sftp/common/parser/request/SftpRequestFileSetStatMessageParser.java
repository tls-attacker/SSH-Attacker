/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpFileAttributesParser;

public class SftpRequestFileSetStatMessageParser
        extends SftpRequestWithHandleMessageParser<SftpRequestFileSetStatMessage> {

    public SftpRequestFileSetStatMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestFileSetStatMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestFileSetStatMessage createMessage() {
        return new SftpRequestFileSetStatMessage();
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithHandleSpecificContents() {
        parseAttributes();
    }
}
