package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPubkeyMessagePreparator extends SshMessagePreparator<UserAuthPubkeyMessage> {

    public UserAuthPubkeyMessagePreparator(Chooser chooser, UserAuthPubkeyMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setUserName(chooser.getConfig().getUsername(), true);
        getObject().setServiceName(ServiceType.SSH_USERAUTH, true);
        getObject().setMethodName(AuthenticationMethod.PUBLICKEY, true);
        getObject().setUseSignature(false);
        getObject().setPubkeyAlgName(chooser.getConfig().getPubkeyAlgName(), true);
        getObject().setPubkey(chooser.getConfig().getPubkey(), true);
    }
}
