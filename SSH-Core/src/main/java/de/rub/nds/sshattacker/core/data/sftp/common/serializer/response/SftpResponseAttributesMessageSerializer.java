/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.response.SftpResponseAttributesMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpResponseAttributesMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseAttributesMessage> {

    private static void serializeAttributes(
            SftpResponseAttributesMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseAttributesMessage object, SerializerStream output) {
        serializeAttributes(object, output);
    }
}
