/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.common.parser.request.SftpRequestWithPathMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestMakeDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder.SftpV4FileAttributesParser;

public class SftpV4RequestMakeDirMessageParser
        extends SftpRequestWithPathMessageParser<SftpV4RequestMakeDirMessage> {

    public SftpV4RequestMakeDirMessageParser(byte[] array) {
        super(array);
    }

    public SftpV4RequestMakeDirMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpV4RequestMakeDirMessage createMessage() {
        return new SftpV4RequestMakeDirMessage();
    }

    private void parseAttributes() {
        SftpV4FileAttributesParser attributesParser =
                new SftpV4FileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseAttributes();
    }
}
