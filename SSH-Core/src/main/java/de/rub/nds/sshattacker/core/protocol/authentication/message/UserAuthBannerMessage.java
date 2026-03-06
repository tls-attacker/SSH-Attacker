/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshField;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class UserAuthBannerMessage extends SshMessage<UserAuthBannerMessage> {

    public static final SshField<ModifiableString> MESSAGE =
            SshField.string("message", StandardCharsets.UTF_8);
    public static final SshField<ModifiableString> LANGUAGE_TAG =
            SshField.string("language_tag", StandardCharsets.US_ASCII);

    private static final List<SshField<?>> FIELDS = List.of(MESSAGE, LANGUAGE_TAG);

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
        setField(MESSAGE, "", true);
        setField(LANGUAGE_TAG, "", true);
    }

    @Override
    public void adjustContext(SshContext context) {
        // TODO: Handle UserAuthBannerMessage
    }
}
