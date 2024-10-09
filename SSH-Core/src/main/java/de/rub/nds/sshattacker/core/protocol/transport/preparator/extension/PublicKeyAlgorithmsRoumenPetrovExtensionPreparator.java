package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PublicKeyAlgorithmsRoumenPetrovExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class PublicKeyAlgorithmsRoumenPetrovExtensionPreparator extends AbstractExtensionPreparator<PublicKeyAlgorithmsRoumenPetrovExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PublicKeyAlgorithmsRoumenPetrovExtensionPreparator(Chooser chooser, PublicKeyAlgorithmsRoumenPetrovExtension extension) {
        super(chooser, extension);
    }

    @Override
    protected void prepareExtensionSpecificContents() {
        // Hier kannst du spezifische Vorbereitungslogik für die Extension hinzufügen
        LOGGER.debug("Preparing PublicKeyAlgorithmsRoumenPetrovExtension...");

        // Setze den Wert der Algorithmen aus dem Chooser
        getObject().setPublicKeyAlgorithms(chooser.getServerSupportedPublicKeyAlgorithmsForAuthentication(), true);
    }

}
