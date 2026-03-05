/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshDataType;
import de.rub.nds.sshattacker.core.protocol.common.SshFieldDefinition;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class UserAuthBannerMessage extends SshMessage<UserAuthBannerMessage> {

    public static final String MESSAGE = "message";
    public static final String LANGUAGE_TAG = "language_tag";

    private static final List<SshFieldDefinition> FIELDS =
            List.of(
                    new SshFieldDefinition(MESSAGE, SshDataType.STRING, StandardCharsets.UTF_8),
                    new SshFieldDefinition(
                            LANGUAGE_TAG, SshDataType.STRING, StandardCharsets.US_ASCII));

    public UserAuthBannerMessage() {
        super(MessageIdConstant.SSH_MSG_USERAUTH_BANNER, FIELDS);
    }

    public UserAuthBannerMessage(UserAuthBannerMessage other) {
        super(other);
    }

    @Override
    public UserAuthBannerMessage createCopy() {
        return new UserAuthBannerMessage(this);
    }

    @Override
    protected UserAuthBannerMessage createNewInstance() {
        return new UserAuthBannerMessage();
    }

    @Override
    protected void prepareMessageContents(Chooser chooser) {
        // TODO dummy values for fuzzing
        setStringField(MESSAGE, "", true);
        setStringField(LANGUAGE_TAG, "", true);
    }

    @Override
    public void adjustContext(SshContext context) {
        // TODO: Handle UserAuthBannerMessage
    }
}
