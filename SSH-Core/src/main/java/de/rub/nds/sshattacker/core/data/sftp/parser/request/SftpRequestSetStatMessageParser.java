/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpFileAttributesParser;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestSetStatMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestSetStatMessage> {

    private final Chooser chooser;

    public SftpRequestSetStatMessageParser(byte[] array, Chooser chooser) {
        super(array);
        this.chooser = chooser;
    }

    public SftpRequestSetStatMessageParser(byte[] array, int startPosition, Chooser chooser) {
        super(array, startPosition);
        this.chooser = chooser;
    }

    @Override
    public SftpRequestSetStatMessage createMessage() {
        return new SftpRequestSetStatMessage();
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
