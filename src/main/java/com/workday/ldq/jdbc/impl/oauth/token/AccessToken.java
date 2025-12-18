/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth.token;

import java.util.Date;

/**
 * Represents an Access Token.
 *
 */
public abstract class AccessToken {

    private final Date expiryTime;
    private final String token;
    private final String idToken;
    private final String tenant;
    private final String subject;
    private final String clientId;

    protected AccessToken(final String token,
                          final Date expiryTime,
                          final String idToken,
                          final String tenant,
                          final String subject,
                          final String clientId) {
        this.expiryTime = expiryTime;
        this.token = token;
        this.idToken = idToken;
        this.tenant = tenant;
        this.subject = subject;
        this.clientId = clientId;
    }

    /**
     * Returns the type of this access token.
     *
     * @return the token type (e.g., "Bearer")
     */
    public abstract String getType();

    public Date getExpiryTime() {
        return this.expiryTime != null ? new Date(this.expiryTime.getTime()) : null;
    }

    public String getToken() {
        return this.token;
    }

    public String getIdToken() {
        return this.idToken;
    }

    public String getTenant() {
        return this.tenant;
    }

    public String getSubject() {
        return this.subject;
    }

    public String getClientId() {
        return this.clientId;
    }
}
