package de.rub.nds.sshattacker.core.protocol.transport.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.PublicKeyAlgorithmsRoumenPetrovExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

public class PublicKeyAlgorithmsRoumenPetrovExtension extends AbstractExtension<PublicKeyAlgorithmsRoumenPetrovExtension> {

    private ModifiableInteger publicKeyAlgorithmsLength;
    private ModifiableString publicKeyAlgorithms;

    public ModifiableInteger getPublicKeyAlgorithmsLength() {
        return publicKeyAlgorithmsLength;
    }

    public void setPublicKeyAlgorithmsLength(ModifiableInteger publicKeyAlgorithmsLength) {
        this.publicKeyAlgorithmsLength = publicKeyAlgorithmsLength;
    }

    public void setPublicKeyAlgorithmsLength(int publicKeyAlgorithmsLength) {
        this.publicKeyAlgorithmsLength = ModifiableVariableFactory.safelySetValue(this.publicKeyAlgorithmsLength, publicKeyAlgorithmsLength);
    }

    public ModifiableString getPublicKeyAlgorithms() {
        return publicKeyAlgorithms;
    }

    public void setPublicKeyAlgorithms(ModifiableString publicKeyAlgorithms) {
        this.publicKeyAlgorithms = publicKeyAlgorithms;
    }

    public void setPublicKeyAlgorithms(String publicKeyAlgorithms) {
        this.publicKeyAlgorithms = ModifiableVariableFactory.safelySetValue(this.publicKeyAlgorithms, publicKeyAlgorithms);
    }

    // Add this method to return the accepted public key algorithms
    public ModifiableString getAcceptedPublicKeyAlgorithms() {
        return publicKeyAlgorithms;
    }

    // New method to set PublicKeyAlgorithm list and adjust length if needed
    public void setPublicKeyAlgorithms(List<PublicKeyAlgorithm> publicKeyAlgorithms, boolean adjustLengthField) {
        // Convert the list of PublicKeyAlgorithm to a comma-separated string
        String nameList = publicKeyAlgorithms.stream()
                .map(PublicKeyAlgorithm::toString)
                .collect(Collectors.joining(","));

        // Set the publicKeyAlgorithms field using the existing method
        setPublicKeyAlgorithms(nameList);

        // Adjust the length field if required
        if (adjustLengthField) {
            setPublicKeyAlgorithmsLength(nameList.getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    @Override
    public PublicKeyAlgorithmsRoumenPetrovExtensionHandler getHandler(SshContext context) {
        return new PublicKeyAlgorithmsRoumenPetrovExtensionHandler(context, this);
    }
}
