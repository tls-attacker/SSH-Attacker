package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
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
        getObject().setServiceName(ServiceType.SSH_CONNECTION, true);
        getObject().setMethodName(AuthenticationMethod.PUBLICKEY, true);
        getObject().setUseSignature(false);
        SshPublicKey<?,?> pk = PublicKeyHelper.parse(chooser.getConfig().getPubkey());
        getObject().setPubkeyAlgName(pk.getPublicKeyFormat().getName(), true);
        getObject().setPubkey(PublicKeyHelper.encode(pk), true);
    }
}