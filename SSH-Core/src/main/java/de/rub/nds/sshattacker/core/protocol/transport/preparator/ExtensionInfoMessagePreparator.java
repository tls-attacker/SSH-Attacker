package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ExtensionInfoMessagePreparator extends SshMessagePreparator<ExtensionInfoMessage> {

    public ExtensionInfoMessagePreparator(Chooser chooser, ExtensionInfoMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        if(chooser.getContext().isClient()) {
            getObject().setNumberExtensions(Converter.intToByteArray(chooser.getNumberExtensionsOfClient()));
            getObject().setExtensions(chooser.getExtensionsOfClient());
        }
        else {
            getObject().setNumberExtensions(Converter.intToByteArray(chooser.getNumberExtensionsOfServer()));
            getObject().setExtensions(chooser.getExtensionsOfServer());
        }
    }
}
