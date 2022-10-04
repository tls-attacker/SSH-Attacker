package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.util.Converter;

public class ServerSigAlgsExtensionParser extends ExtensionParser {

    public ServerSigAlgsExtensionParser(byte[] extension) {
        super(extension);
    }

    @Override
    public byte[] parseExtensionName() {
        byte[] extensionNameLength = super.parseByteArrayField(DataFormatConstants.UINT32_SIZE);
        byte[] extName = super.parseByteArrayField(Converter.byteArrayToInt(extensionNameLength));
        return extName;
    }

    @Override
    public byte[] parseExtensionValue() {
        byte[] extensionValueLength = super.parseByteArrayField(DataFormatConstants.UINT32_SIZE);
        byte[] extValue = super.parseByteArrayField(Converter.byteArrayToInt(extensionValueLength));
        return extValue;
    }

    @Override
    public ServerSigAlgsExtension parse() {
        byte[] extensionName = this.parseExtensionName();
        byte[] extensionValue = this.parseExtensionValue();
        ModifiableString name = Converter.byteArrayToModifiableString(extensionName);
        ModifiableString value = Converter.byteArrayToModifiableString(extensionValue);
        ServerSigAlgsExtension ext = new ServerSigAlgsExtension(name, value);
        return ext;
    }

}
