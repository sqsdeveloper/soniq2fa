// SPDX-FileCopyrightText: 2026 SoniqSoft sp. z o.o.
// SPDX-License-Identifier: GPL-2.0-or-later
package pl.soniqsoft.soniq2fa;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.auth.ZimbraCustomAuth;
import com.zimbra.cs.extension.ExtensionDispatcherServlet;
import com.zimbra.cs.extension.ZimbraExtension;

/** Loaded from /opt/zextras/lib/ext/soniq2fa/ via the Zimbra-Extension-Class manifest entry. */
public final class Soniq2faExtension implements ZimbraExtension {
    @Override
    public String getName() {
        return "soniq2fa";
    }

    @Override
    public void init() throws ServiceException {
        ZimbraCustomAuth.register("soniq2fa", new Soniq2faAuth());
        if (!Soniq2faAuth.Jetty.available())
            ZimbraLog.account.error("soniq2fa: unknown Jetty version, SMTP AUTH cannot be recognised; enrolled users' "
                    + "SMTP AUTH with device passwords will be refused until the extension is updated");
        ExtensionDispatcherServlet.register(this, new Soniq2faPage());
        ExtensionDispatcherServlet.register(this, new Soniq2faAdmin());
        ExtensionDispatcherServlet.register(this, new Soniq2faRecovery());
    }

    @Override
    public void destroy() {
        ExtensionDispatcherServlet.unregister(this);
    }
}
