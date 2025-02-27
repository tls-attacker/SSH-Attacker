/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.parser.response;

import de.rub.nds.sshattacker.core.data.sftp.common.parser.response.SftpResponseMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseAttributesMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.holder.SftpV4FileAttributesParser;

public class SftpV4ResponseAttributesMessageParser
        extends SftpResponseMessageParser<SftpV4ResponseAttributesMessage> {

    public SftpV4ResponseAttributesMessageParser(byte[] array) {
        super(array);
    }

    public SftpV4ResponseAttributesMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpV4ResponseAttributesMessage createMessage() {
        return new SftpV4ResponseAttributesMessage();
    }

    private void parseAttributes() {
        SftpV4FileAttributesParser attributesParser =
                new SftpV4FileAttributesParser(getArray(), getPointer());
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseAttributes();
    }
}
