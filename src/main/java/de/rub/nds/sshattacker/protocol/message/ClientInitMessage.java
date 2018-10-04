/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Message;

/**
 *
 * @author spotz
 */
public class ClientInitMessage extends Message {

    /**
     * version identifier + optional comment
     */
    private ModifiableString version;
    private ModifiableString yrdy;

    public ClientInitMessage() {
    }

    public ModifiableString getVersion() {
        return version;
    }

    public void setVersion(ModifiableString version) {
        this.version = version;
    }
    
    public void setVersion(String version)
    {
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }

    public ModifiableString getComment() {
        return yrdy;
    }

    public void setComment(String comment) {
        this.yrdy = ModifiableVariableFactory.safelySetValue(this.yrdy, comment);
    }
    
    public void setComment(ModifiableString comment) {
        this.yrdy = comment;
    }
    
    @Override
    public String toCompactString() {
        return "ClientInitMessage";
    }
    
}
