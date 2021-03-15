package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class KeyExchangeInitMessagePreparator extends Preparator<KeyExchangeInitMessage> {

    public KeyExchangeInitMessagePreparator(SshContext context, KeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEXINIT.id);
        message.setCookie(context.getChooser().getClientCookie());
        message.setKeyExchangeAlgorithms(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedKeyExchangeAlgorithms()));
        message.setKeyExchangeAlgorithmsLength(message.getKeyExchangeAlgorithms().getValue().length());
        message.setServerHostKeyAlgorithms(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedHostKeyAlgorithms()));
        message.setServerHostKeyAlgorithmsLength(message.getServerHostKeyAlgorithms().getValue().length());
        message.setEncryptionAlgorithmsClientToServer(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedCipherAlgorithmsClientToServer()));
        message.setEncryptionAlgorithmsClientToServerLength(message.getEncryptionAlgorithmsClientToServer().getValue().length());
        message.setEncryptionAlgorithmsServerToClient(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedCipherAlgorithmsServertoClient()));
        message.setEncryptionAlgorithmsServerToClientLength(message.getEncryptionAlgorithmsServerToClient().getValue().length());
        message.setMacAlgorithmsClientToServer(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedMacAlgorithmsClientToServer()));
        message.setMacAlgorithmsClientToServerLength(message.getMacAlgorithmsClientToServer().getValue().length());
        message.setMacAlgorithmsServerToClient(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedMacAlgorithmsServerToClient()));
        message.setMacAlgorithmsServerToClientLength(message.getMacAlgorithmsServerToClient().getValue().length());
        message.setCompressionAlgorithmsClientToServer(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedCompressionAlgorithmsClientToServer()));
        message.setCompressionAlgorithmsClientToServerLength(message.getCompressionAlgorithmsClientToServer().getValue().length());
        message.setCompressionAlgorithmsServerToClient(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedCompressionAlgorithmsServerToClient()));
        message.setCompressionAlgorithmsServerToClientLength(message.getCompressionAlgorithmsServerToClient().getValue().length());
        message.setLanguagesClientToServer(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedLanguagesClientToServer()));
        message.setLanguagesClientToServerLength(message.getLanguagesClientToServer().getValue().length());
        message.setLanguagesServerToClient(Converter.listofAlgorithmstoString(context.getChooser().getClientSupportedLanguagesServerToClient()));
        message.setLanguagesServerToClientLength(message.getLanguagesServerToClient().getValue().length());
        message.setFirstKeyExchangePacketFollows(context.getChooser().getClientFirstKeyExchangePacketFollows());
        message.setReserved(context.getChooser().getClientReserved());

        context.appendToExchangeHashInput(new KeyExchangeInitMessageSerializer(message).serialize());
    }
}
