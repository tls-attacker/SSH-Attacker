/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PublicKeyAlgorithmsRoumenPetrovExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class PublicKeyAlgorithmsRoumenPetrovExtensionPreparator
        extends AbstractExtensionPreparator<PublicKeyAlgorithmsRoumenPetrovExtension> {

    public PublicKeyAlgorithmsRoumenPetrovExtensionPreparator() {
        super(Extension.PUBLICKEY_ALGORITHMS_ROUMENPETROV);
    }

    @Override
    protected void prepareExtensionSpecificContents(
            PublicKeyAlgorithmsRoumenPetrovExtension object, Chooser chooser) {
        object.setSoftlyPublicKeyAlgorithms(
                chooser.getServerSupportedPublicKeyAlgorithmsForAuthentication(),
                true,
                chooser.getConfig());
    }
}
