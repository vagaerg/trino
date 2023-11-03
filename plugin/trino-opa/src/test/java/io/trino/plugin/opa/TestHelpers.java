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
package io.trino.plugin.opa;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import io.trino.execution.QueryIdGenerator;
import io.trino.plugin.opa.HttpClientUtils.InstrumentedHttpClient;
import io.trino.plugin.opa.HttpClientUtils.MockResponse;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.Identity;
import io.trino.spi.security.SystemSecurityContext;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.common.net.MediaType.JSON_UTF_8;

public class TestHelpers
{
    private TestHelpers() {}

    public static final MockResponse OK_RESPONSE = new MockResponse("""
            {
                "decision_id": "",
                "result": true
            }
            """,
            200);
    public static final MockResponse NO_ACCESS_RESPONSE = new MockResponse("""
            {
                "decision_id": "",
                "result": false
            }
            """,
            200);
    public static final MockResponse MALFORMED_RESPONSE = new MockResponse("""
            { "this"": is broken_json; }
            """,
            200);
    public static final MockResponse UNDEFINED_RESPONSE = new MockResponse("{}", 404);
    public static final MockResponse BAD_REQUEST_RESPONSE = new MockResponse("{}", 400);
    public static final MockResponse SERVER_ERROR_RESPONSE = new MockResponse("", 500);

    public static Stream<Arguments> createFailingTestCases(Stream<Arguments> baseTestCases)
    {
        return Sets.cartesianProduct(
                        baseTestCases.collect(toImmutableSet()),
                        allErrorCasesArgumentProvider().collect(toImmutableSet()))
                .stream()
                .map(items -> Arguments.of(items.stream().flatMap((args) -> Arrays.stream(args.get())).toArray()));
    }

    public static Stream<Arguments> createIllegalResponseTestCases(Stream<Arguments> baseTestCases)
    {
        return Sets.cartesianProduct(
                        baseTestCases.collect(toImmutableSet()),
                        illegalResponseArgumentProvider().collect(toImmutableSet()))
                .stream()
                .map(items -> Arguments.of(items.stream().flatMap((args) -> Arrays.stream(args.get())).toArray()));
    }

    public static Stream<Arguments> illegalResponseArgumentProvider()
    {
        // Invalid responses from OPA
        return Stream.of(
                Arguments.of(Named.of("Undefined policy response", UNDEFINED_RESPONSE), OpaQueryException.OpaServerError.PolicyNotFound.class, "did not return a value"),
                Arguments.of(Named.of("Bad request response", BAD_REQUEST_RESPONSE), OpaQueryException.OpaServerError.class, "returned status 400"),
                Arguments.of(Named.of("Server error response", SERVER_ERROR_RESPONSE), OpaQueryException.OpaServerError.class, "returned status 500"),
                Arguments.of(Named.of("Malformed JSON response", MALFORMED_RESPONSE), OpaQueryException.class, "Failed to deserialize"));
    }

    public static Stream<Arguments> allErrorCasesArgumentProvider()
    {
        // All possible failure scenarios, including a well-formed access denied response
        return Stream.concat(
                illegalResponseArgumentProvider(),
                Stream.of(Arguments.of(Named.of("No access response", NO_ACCESS_RESPONSE), AccessDeniedException.class, "Access Denied")));
    }

    public static SystemSecurityContext systemSecurityContextFromIdentity(Identity identity) {
        return new SystemSecurityContext(identity, new QueryIdGenerator().createNextQueryId(), Instant.now());
    }

    public abstract static class MethodWrapper<T> {
        public abstract boolean isAccessAllowed(OpaAccessControl opaAccessControl, SystemSecurityContext systemSecurityContext, T argument);
    }

    public static class ThrowingMethodWrapper<T> extends MethodWrapper<T> {
        private final FunctionalHelpers.Consumer3<OpaAccessControl, SystemSecurityContext, T> callable;

        public ThrowingMethodWrapper(FunctionalHelpers.Consumer3<OpaAccessControl, SystemSecurityContext, T> callable) {
            this.callable = callable;
        }

        @Override
        public boolean isAccessAllowed(OpaAccessControl opaAccessControl, SystemSecurityContext systemSecurityContext, T argument) {
            try {
                this.callable.accept(opaAccessControl, systemSecurityContext, argument);
                return true;
            } catch (AccessDeniedException e) {
                return false;
            }
        }
    }

    public static class ReturningMethodWrapper<T> extends MethodWrapper<T> {
        private final FunctionalHelpers.Function3<OpaAccessControl, SystemSecurityContext, T, Boolean> callable;

        public ReturningMethodWrapper(FunctionalHelpers.Function3<OpaAccessControl, SystemSecurityContext, T, Boolean> callable) {
            this.callable = callable;
        }

        @Override
        public boolean isAccessAllowed(OpaAccessControl opaAccessControl, SystemSecurityContext systemSecurityContext, T argument) {
            return this.callable.apply(opaAccessControl, systemSecurityContext, argument);
        }
    }

    public static InstrumentedHttpClient createMockHttpClient(URI expectedUri, Function<JsonNode, MockResponse> handler)
    {
        return new InstrumentedHttpClient(expectedUri, "POST", JSON_UTF_8.toString(), handler);
    }

    public static OpaAccessControl createOpaAuthorizer(URI opaUri, InstrumentedHttpClient mockHttpClient)
    {
        return (OpaAccessControl) OpaAccessControlFactory.create(ImmutableMap.of("opa.policy.uri", opaUri.toString()), Optional.of(mockHttpClient));
    }

    public static OpaAccessControl createOpaAuthorizer(URI opaUri, URI opaBatchUri, InstrumentedHttpClient mockHttpClient)
    {
        return (OpaAccessControl) OpaAccessControlFactory.create(
                ImmutableMap.<String, String>builder()
                        .put("opa.policy.uri", opaUri.toString())
                        .put("opa.policy.batched-uri", opaBatchUri.toString())
                        .buildOrThrow(),
                Optional.of(mockHttpClient));
    }
}
