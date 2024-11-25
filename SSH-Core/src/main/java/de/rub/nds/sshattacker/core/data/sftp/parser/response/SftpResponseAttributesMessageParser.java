/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.response;

import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseAttributesMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseAttributesMessageParser
        extends SftpResponseMessageParser<SftpResponseAttributesMessage> {

    private final Chooser chooser;

    public SftpResponseAttributesMessageParser(byte[] array, Chooser chooser) {
        super(array);
        this.chooser = chooser;
    }

    public SftpResponseAttributesMessageParser(byte[] array, int startPosition, Chooser chooser) {
        super(array, startPosition);
        this.chooser = chooser;
    }

    @Override
    public SftpResponseAttributesMessage createMessage() {
        return new SftpResponseAttributesMessage();
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer(), chooser);
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseAttributes();
    }
}
