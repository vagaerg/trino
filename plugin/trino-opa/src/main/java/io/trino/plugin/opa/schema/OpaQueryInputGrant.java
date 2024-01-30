/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.opa.schema;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.collect.ImmutableSet;
import io.trino.spi.security.Privilege;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;
import static java.util.Objects.requireNonNull;

@JsonInclude(NON_NULL)
public record OpaQueryInputGrant(@NotNull Set<TrinoGrantPrincipal> principals, Boolean grantOption, String privilege)
{
    public OpaQueryInputGrant
    {
        principals = ImmutableSet.copyOf(requireNonNull(principals, "principals is null"));
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private Set<TrinoGrantPrincipal> principals;
        private Boolean grantOption;
        private String privilege;

        private Builder() {}

        public Builder principal(TrinoGrantPrincipal principal)
        {
            this.principals = ImmutableSet.of(principal);
            return this;
        }

        public Builder principals(Set<TrinoGrantPrincipal> principals)
        {
            this.principals = principals;
            return this;
        }

        public Builder grantOption(boolean grantOption)
        {
            this.grantOption = grantOption;
            return this;
        }

        public Builder privilege(Privilege privilege)
        {
            this.privilege = privilege.name();
            return this;
        }

        public OpaQueryInputGrant build()
        {
            return new OpaQueryInputGrant(this.principals, this.grantOption, this.privilege);
        }
    }
}
