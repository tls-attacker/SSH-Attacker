/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.constants.HashAlgorithm;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestCheckFileHandleMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

public class SftpRequestCheckFileHandleMessage
        extends SftpRequestExtendedWithHandleMessage<SftpRequestCheckFileHandleMessage> {

    private ModifiableInteger hashAlgorithmsLength;
    private ModifiableString hashAlgorithms;
    private ModifiableLong startOffset;
    private ModifiableLong length;
    private ModifiableInteger blockSize;

    public ModifiableInteger getHashAlgorithmsLength() {
        return hashAlgorithmsLength;
    }

    public void setHashAlgorithmsLength(ModifiableInteger hashAlgorithmsLength) {
        this.hashAlgorithmsLength = hashAlgorithmsLength;
    }

    public void setHashAlgorithmsLength(int hashAlgorithmsLength) {
        this.hashAlgorithmsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.hashAlgorithmsLength, hashAlgorithmsLength);
    }

    public ModifiableString getHashAlgorithms() {
        return hashAlgorithms;
    }

    public void setHashAlgorithms(ModifiableString hashAlgorithms) {
        setHashAlgorithms(hashAlgorithms, false);
    }

    public void setHashAlgorithms(String hashAlgorithms) {
        setHashAlgorithms(hashAlgorithms, false);
    }

    public void setHashAlgorithms(String[] hashAlgorithms) {
        setHashAlgorithms(hashAlgorithms, false);
    }

    public void setHashAlgorithms(List<HashAlgorithm> hashAlgorithms) {
        setHashAlgorithms(hashAlgorithms, false);
    }

    public void setHashAlgorithms(ModifiableString hashAlgorithms, boolean adjustLengthField) {
        this.hashAlgorithms = hashAlgorithms;
        if (adjustLengthField) {
            setHashAlgorithmsLength(
                    this.hashAlgorithms.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setHashAlgorithms(String hashAlgorithms, boolean adjustLengthField) {
        this.hashAlgorithms =
                ModifiableVariableFactory.safelySetValue(this.hashAlgorithms, hashAlgorithms);
        if (adjustLengthField) {
            setHashAlgorithmsLength(
                    this.hashAlgorithms.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setHashAlgorithms(String[] hashAlgorithms, boolean adjustLengthField) {
        String nameList = String.join("" + CharConstants.ALGORITHM_SEPARATOR, hashAlgorithms);
        setHashAlgorithms(nameList, adjustLengthField);
    }

    public void setHashAlgorithms(List<HashAlgorithm> hashAlgorithms, boolean adjustLengthField) {
        String nameList =
                hashAlgorithms.stream()
                        .map(HashAlgorithm::toString)
                        .collect(Collectors.joining("" + CharConstants.ALGORITHM_SEPARATOR));
        setHashAlgorithms(nameList, adjustLengthField);
    }

    public ModifiableLong getStartOffset() {
        return startOffset;
    }

    public void setStartOffset(ModifiableLong startOffset) {
        this.startOffset = startOffset;
    }

    public void setStartOffset(long startOffset) {
        this.startOffset = ModifiableVariableFactory.safelySetValue(this.startOffset, startOffset);
    }

    public ModifiableLong getLength() {
        return length;
    }

    public void setLength(ModifiableLong length) {
        this.length = length;
    }

    public void setLength(long length) {
        this.length = ModifiableVariableFactory.safelySetValue(this.length, length);
    }

    public ModifiableInteger getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(ModifiableInteger blockSize) {
        this.blockSize = blockSize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = ModifiableVariableFactory.safelySetValue(this.blockSize, blockSize);
    }

    @Override
    public SftpRequestCheckFileHandleMessageHandler getHandler(SshContext context) {
        return new SftpRequestCheckFileHandleMessageHandler(context, this);
    }
}
