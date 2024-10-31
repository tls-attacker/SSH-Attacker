/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseAttributesMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpFileAttributesParser;

public class SftpResponseAttributesMessageParser
        extends SftpResponseMessageParser<SftpResponseAttributesMessage> {

    public SftpResponseAttributesMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseAttributesMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseAttributesMessage createMessage() {
        return new SftpResponseAttributesMessage();
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseAttributes();
    }
}
