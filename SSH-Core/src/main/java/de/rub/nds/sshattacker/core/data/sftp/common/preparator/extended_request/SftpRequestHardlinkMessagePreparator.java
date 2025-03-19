/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestHardlinkMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestHardlinkMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestHardlinkMessage> {

    public SftpRequestHardlinkMessagePreparator() {
        super(SftpExtension.HARDLINK_OPENSSH_COM);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestHardlinkMessage object, Chooser chooser) {

        object.setPath("/etc/passwd", true);

        object.setNewPath("/etc/passwd-new", true);
    }
}
