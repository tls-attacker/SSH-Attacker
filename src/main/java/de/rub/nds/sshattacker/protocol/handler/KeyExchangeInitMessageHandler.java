package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MACAlgorithm;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class KeyExchangeInitMessageHandler extends Handler<KeyExchangeInitMessage> {

    public KeyExchangeInitMessageHandler(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void handle() {
        // TODO currently only handling for server messages
        context.setServerCookie(message.getCookie().getValue());
        context.setServerSupportedKeyExchangeAlgorithms(Converter.StringToAlgorithms(message.getKeyExchangeAlgorithms().getValue(), KeyExchangeAlgorithm.class));
        context.setServerSupportedHostKeyAlgorithms(Converter.StringToAlgorithms(message.getServerHostKeyAlgorithms().getValue(), PublicKeyAuthenticationAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getEncryptionAlgorithmsClientToServer().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedCipherAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getEncryptionAlgorithmsServerToClient().getValue(), EncryptionAlgorithm.class));
        context.setServerSupportedMacAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getMacAlgorithmsClientToServer().getValue(), MACAlgorithm.class));
        context.setServerSupportedMacAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getMacAlgorithmsServerToClient().getValue(), MACAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsClientToServer(Converter.StringToAlgorithms(message.getCompressionAlgorithmsClientToServer().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedCompressionAlgorithmsServerToClient(Converter.StringToAlgorithms(message.getCompressionAlgorithmsServerToClient().getValue(), CompressionAlgorithm.class));
        context.setServerSupportedLanguagesClientToServer(Converter.StringToAlgorithms(message.getLanguagesClientToServer().getValue(), Language.class));
        context.setServerSupportedLanguagesServerToClient(Converter.StringToAlgorithms(message.getLanguagesServerToClient().getValue(), Language.class));
        context.setServerReserved(message.getReserved().getValue());
    }
}
