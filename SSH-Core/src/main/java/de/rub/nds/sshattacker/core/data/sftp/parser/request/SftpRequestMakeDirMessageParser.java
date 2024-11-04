/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestMakeDirMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestMakeDirMessage> {

    private final Chooser chooser;

    public SftpRequestMakeDirMessageParser(byte[] array, Chooser chooser) {
        super(array);
        this.chooser = chooser;
    }

    public SftpRequestMakeDirMessageParser(byte[] array, int startPosition, Chooser chooser) {
        super(array, startPosition);
        this.chooser = chooser;
    }

    @Override
    public SftpRequestMakeDirMessage createMessage() {
        return new SftpRequestMakeDirMessage();
    }

    private void parseAttributes() {
        SftpFileAttributesParser attributesParser =
                new SftpFileAttributesParser(getArray(), getPointer(), chooser);
        message.setAttributes(attributesParser.parse());
        setPointer(attributesParser.getPointer());
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseAttributes();
    }
}
