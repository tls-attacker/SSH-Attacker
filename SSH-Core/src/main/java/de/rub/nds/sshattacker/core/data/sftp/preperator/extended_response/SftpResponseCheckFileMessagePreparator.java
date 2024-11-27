/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response;

import de.rub.nds.sshattacker.core.constants.HashAlgorithm;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseCheckFileMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseCheckFileMessagePreparator
        extends SftpResponseExtendedMessagePreparator<SftpResponseCheckFileMessage> {

    public SftpResponseCheckFileMessagePreparator(
            Chooser chooser, SftpResponseCheckFileMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareResponseSpecificContents() {
        if (getObject().getUsedHashAlgorithm() == null
                || getObject().getUsedHashAlgorithm().getOriginalValue() == null) {
            getObject().setUsedHashAlgorithm(HashAlgorithm.MD5, true);
        }
        if (getObject().getUsedHashAlgorithmLength() == null
                || getObject().getUsedHashAlgorithmLength().getOriginalValue() == null) {
            getObject()
                    .setUsedHashAlgorithmLength(
                            getObject().getUsedHashAlgorithm().getValue().length());
        }

        if (getObject().getHash() == null || getObject().getHash().getOriginalValue() == null) {
            getObject().setHash(new byte[100]);
        }
    }
}
