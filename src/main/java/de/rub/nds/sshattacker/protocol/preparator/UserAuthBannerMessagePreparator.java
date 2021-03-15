package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthBannerMessagePreparator extends Preparator<UserAuthBannerMessage> {

    public UserAuthBannerMessagePreparator(SshContext context, UserAuthBannerMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_BANNER.id);

        // TODO dummy values for fuzzing
        message.setMessage("");
        message.setLanguageTag("");
    }

}
