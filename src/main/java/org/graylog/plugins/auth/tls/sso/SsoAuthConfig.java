/**
 * This file is part of Graylog Archive.
 *
 * Graylog Archive is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog Archive is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog Archive.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.auth.tls.sso;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.google.auto.value.AutoValue;

import javax.annotation.Nullable;

@AutoValue
@JsonDeserialize(builder = AutoValue_SsoAuthConfig.Builder.class)
@JsonAutoDetect
public abstract class SsoAuthConfig {

    public static Builder builder() {
        return new AutoValue_SsoAuthConfig.Builder();
    }

    public abstract Builder toBuilder();

    public static SsoAuthConfig defaultConfig(String trustedProxies) {
        return builder()
                .certificateHeader("tls-client-cert")
                .autoCreateUser(true)
                .requireTrustedProxies(true)
                .trustedProxies(trustedProxies)
                .build();
    }

    @JsonProperty("certificate_header")
    public abstract String certificateHeader();

    @JsonProperty("default_group")
    @Nullable
    public abstract String defaultGroup();

    @JsonProperty("auto_create_user")
    public abstract boolean autoCreateUser();

    @JsonProperty("require_trusted_proxies")
    public abstract boolean requireTrustedProxies();

    @JsonProperty("trusted_proxies")
    @Nullable
    public abstract String trustedProxies();

    @AutoValue.Builder
    public static abstract class Builder {
        abstract SsoAuthConfig build();

        @JsonProperty("certificate_header")
        public abstract Builder certificateHeader(String certificateHeader);

        @JsonProperty("default_group")
        public abstract Builder defaultGroup(@Nullable String defaultGroup);

        @JsonProperty("auto_create_user")
        public abstract Builder autoCreateUser(boolean autoCreateUser);

        @JsonProperty("require_trusted_proxies")
        public abstract Builder requireTrustedProxies(boolean requireTrustedProxies);

        @JsonProperty("trusted_proxies")
        public abstract Builder trustedProxies(@Nullable String trustedProxies);

    }
}

