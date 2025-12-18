/*
 * Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package com.workday.ldq.jdbc.impl.oauth.token;

import static com.workday.ldq.jdbc.impl.property.DriverPropertyUtil.IS_NOT_EMPTY;

import java.util.Date;

import com.workday.ldq.jdbc.api.exception.LDQJdbcDriverRuntimeException;

/**
 * Represents a Bearer Access Token.
 *
 */
public class BearerAccessToken
    extends AccessToken {

    public static final String TYPE_BEARER = "Bearer";

    public BearerAccessToken(final Builder builder) {
        super(
            builder.token,
            builder.expiryTime,
            builder.tokenId,
            builder.tenant,
            builder.subject,
            builder.clientId
        );
    }

    @Override
    public String getType() {
        return TYPE_BEARER;
    }

    /**
     * Creates a new Builder instance for BearerAccessToken.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for BearerAccessToken using the Builder pattern.
     * Provides a fluent API for constructing BearerAccessToken instances.
     */
    public static class Builder {

        private String token;
        private Date expiryTime;
        private String tokenId;
        private String tenant;
        private String subject;
        private String clientId;

        private Builder() {
            // Private constructor to enforce use of builder() method
        }

        public Builder token(final String token) {
            this.token = token;
            return this;
        }

        public Builder expiryTime(final Object expiryTime) {
            if (expiryTime instanceof Date) {
                this.expiryTime = new Date(((Date) expiryTime).getTime());
            }
            else if (expiryTime instanceof Long) {
                this.expiryTime = new Date((Long) expiryTime);
            }
            else {
                throw new LDQJdbcDriverRuntimeException("expiryTime must be Date or Long");
            }
            return this;
        }

        public Builder idToken(final String idToken) {
            this.tokenId = idToken;
            return this;
        }

        public Builder tenant(final Object tenant) {
            this.tenant = verifyStringClaim(tenant);
            return this;
        }

        public Builder subject(final Object subject) {
            this.subject = verifyStringClaim(subject);
            return this;
        }

        public Builder clientId(final Object clientId) {
            this.clientId = verifyStringClaim(clientId);
            return this;
        }

        public BearerAccessToken build() {
            validate();
            return new BearerAccessToken(this);
        }

        private static String verifyStringClaim(final Object claim) {
            if (claim != null && !(claim instanceof String)) {
                throw new LDQJdbcDriverRuntimeException(
                    String.format("claim must be String, got: %s", claim.getClass().getName()));
            }
            return (String) claim;
        }

        /**
         * Validates that all required fields are set and valid.
         *
         * @throws LDQJdbcDriverRuntimeException if validation fails
         */
        private void validate() {
            if (IS_NOT_EMPTY.negate().test(this.token)) {
                throw new LDQJdbcDriverRuntimeException("Token is required and cannot be null or empty");
            }
            if (this.expiryTime == null || this.expiryTime.getTime() <= 0) {
                throw new LDQJdbcDriverRuntimeException("Expiry time must be greater than 0");
            }
            if (IS_NOT_EMPTY.negate().test(this.clientId)) {
                throw new LDQJdbcDriverRuntimeException("Client ID is required and cannot be null or empty");
            }
        }
    }
}
