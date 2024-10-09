package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PublicKeyAlgorithmsRoumenPetrovExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyAlgorithmsRoumenPetrovExtensionSerializer extends AbstractExtensionSerializer<PublicKeyAlgorithmsRoumenPetrovExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PublicKeyAlgorithmsRoumenPetrovExtensionSerializer(PublicKeyAlgorithmsRoumenPetrovExtension extension) {
        super(extension);
    }

    @Override
    protected void serializeExtensionValue() {
        LOGGER.debug("Serializing PublicKeyAlgorithmsRoumenPetrovExtension...");
        serializePublicKeyAlgorithmsLength();
        serializePublicKeyAlgorithms();
    }

    private void serializePublicKeyAlgorithmsLength() {
        appendInt(extension.getPublicKeyAlgorithmsLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializePublicKeyAlgorithms() {
        appendString(extension.getPublicKeyAlgorithms().getValue(), StandardCharsets.US_ASCII);
    }
}
