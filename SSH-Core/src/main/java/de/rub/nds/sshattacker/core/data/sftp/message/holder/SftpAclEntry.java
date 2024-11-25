/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.holder;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.SftpAceFlag;
import de.rub.nds.sshattacker.core.constants.SftpAceMask;
import de.rub.nds.sshattacker.core.constants.SftpAceType;
import de.rub.nds.sshattacker.core.data.sftp.handler.holder.SftpAclEntryHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.nio.charset.StandardCharsets;

@XmlAccessorType(XmlAccessType.FIELD)
public class SftpAclEntry extends ModifiableVariableHolder {

    private ModifiableInteger type;
    private ModifiableInteger flags;
    private ModifiableInteger mask;
    private ModifiableString who;
    private ModifiableInteger whoLength;

    public ModifiableInteger getType() {
        return type;
    }

    public void setType(ModifiableInteger type) {
        this.type = type;
    }

    public void setType(int type) {
        this.type = ModifiableVariableFactory.safelySetValue(this.type, type);
    }

    public void setType(SftpAceType type) {
        setType(type.getType());
    }

    public ModifiableInteger getFlags() {
        return flags;
    }

    public void setFlags(ModifiableInteger flags) {
        this.flags = flags;
    }

    public void setFlags(int flags) {
        this.flags = ModifiableVariableFactory.safelySetValue(this.flags, flags);
    }

    public void setFlags(SftpAceFlag... flags) {
        setFlags(SftpAceFlag.flagsToInt(flags));
    }

    public ModifiableInteger getMask() {
        return mask;
    }

    public void setMask(ModifiableInteger mask) {
        this.mask = mask;
    }

    public void setMask(int mask) {
        this.mask = ModifiableVariableFactory.safelySetValue(this.mask, mask);
    }

    public void setMask(SftpAceMask... flags) {
        setMask(SftpAceMask.flagsToInt(flags));
    }

    public ModifiableInteger getWhoLength() {
        return whoLength;
    }

    public void setWhoLength(ModifiableInteger whoLength) {
        this.whoLength = whoLength;
    }

    public void setWhoLength(int whoLength) {
        this.whoLength = ModifiableVariableFactory.safelySetValue(this.whoLength, whoLength);
    }

    public ModifiableString getWho() {
        return who;
    }

    public void setWho(ModifiableString who) {
        setWho(who, false);
    }

    public void setWho(String who) {
        setWho(who, false);
    }

    public void setWho(ModifiableString who, boolean adjustLengthField) {
        if (adjustLengthField) {
            setWhoLength(who.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.who = who;
    }

    public void setWho(String who, boolean adjustLengthField) {
        if (adjustLengthField) {
            setWhoLength(who.getBytes(StandardCharsets.UTF_8).length);
        }
        this.who = ModifiableVariableFactory.safelySetValue(this.who, who);
    }

    public SftpAclEntryHandler getHandler(SshContext context) {
        return new SftpAclEntryHandler(context, this);
    }
}
