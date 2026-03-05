/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.response.SftpResponseMessagePreparator;

public abstract class SftpResponseExtendedMessagePreparator<T extends SftpResponseMessage<T>>
        extends SftpResponseMessagePreparator<T> {

    protected SftpResponseExtendedMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_EXTENDED_REPLY);
    }
}
