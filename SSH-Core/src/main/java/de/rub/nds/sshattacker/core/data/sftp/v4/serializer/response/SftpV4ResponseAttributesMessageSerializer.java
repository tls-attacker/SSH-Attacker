/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.serializer.response;

import de.rub.nds.sshattacker.core.data.sftp.common.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseAttributesMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpV4ResponseAttributesMessageSerializer
        extends SftpResponseMessageSerializer<SftpV4ResponseAttributesMessage> {

    private static void serializeAttributes(
            SftpV4ResponseAttributesMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpV4ResponseAttributesMessage object, SerializerStream output) {
        serializeAttributes(object, output);
    }
}
