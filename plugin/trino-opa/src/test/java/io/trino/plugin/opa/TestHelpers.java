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
import com.google.common.collect.ImmutableSet;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Tracer;
import io.trino.execution.QueryIdGenerator;
import io.trino.plugin.opa.HttpClientUtils.InstrumentedHttpClient;
import io.trino.plugin.opa.HttpClientUtils.MockResponse;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.Identity;
import io.trino.spi.security.SystemAccessControlFactory;
import io.trino.spi.security.SystemSecurityContext;

import java.net.URI;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;

import static com.google.common.net.MediaType.JSON_UTF_8;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public final class TestHelpers
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
            200); public static final MockResponse UNDEFINED_RESPONSE = new MockResponse("{}", 404); public static final MockResponse BAD_REQUEST_RESPONSE = new MockResponse("{}", 400);
    public static final MockResponse SERVER_ERROR_RESPONSE = new MockResponse("", 500);
    public static final SystemAccessControlFactory.SystemAccessControlContext SYSTEM_ACCESS_CONTROL_CONTEXT = new TestingSystemAccessControlContext("TEST_VERSION");
    public static final URI OPA_SERVER_URI = URI.create("http://my-uri/");
    public static final URI OPA_SERVER_BATCH_URI = URI.create("http://my-batch-uri/");
    public static final Identity TEST_IDENTITY = Identity.forUser("source-user").withGroups(ImmutableSet.of("some-group")).build();
    public static final SystemSecurityContext TEST_SECURITY_CONTEXT = new SystemSecurityContext(TEST_IDENTITY, new QueryIdGenerator().createNextQueryId(), Instant.now());

    public abstract static class MethodWrapper {
        public abstract boolean isAccessAllowed(OpaAccessControl opaAccessControl);
    }

    public static class ThrowingMethodWrapper extends MethodWrapper {
        private final Consumer<OpaAccessControl> callable;

        public ThrowingMethodWrapper(Consumer<OpaAccessControl> callable) {
            this.callable = callable;
        }

        @Override
        public boolean isAccessAllowed(OpaAccessControl opaAccessControl) {
            try {
                this.callable.accept(opaAccessControl);
                return true;
            } catch (AccessDeniedException e) {
                if (!e.getMessage().contains("Access Denied")) {
                    throw new AssertionError("Expected AccessDenied exception to contain 'Access Denied' in the message");
                }
                return false;
            }
        }
    }

    public static class ReturningMethodWrapper extends MethodWrapper {
        private final Function<OpaAccessControl, Boolean> callable;

        public ReturningMethodWrapper(Function<OpaAccessControl, Boolean> callable) {
            this.callable = callable;
        }

        @Override
        public boolean isAccessAllowed(OpaAccessControl opaAccessControl) {
            return this.callable.apply(opaAccessControl);
        }
    }

    public static InstrumentedHttpClient createMockHttpClient(URI expectedUri, Function<JsonNode, MockResponse> handler)
    {
        return new InstrumentedHttpClient(expectedUri, "POST", JSON_UTF_8.toString(), handler);
    }

    public static OpaAccessControl createOpaAuthorizer(URI opaUri, InstrumentedHttpClient mockHttpClient)
    {
        return (OpaAccessControl) OpaAccessControlFactory.create(ImmutableMap.of("opa.policy.uri", opaUri.toString()), Optional.of(mockHttpClient), Optional.of(SYSTEM_ACCESS_CONTROL_CONTEXT));
    }

    public static OpaAccessControl createOpaAuthorizer(URI opaUri, URI opaBatchUri, InstrumentedHttpClient mockHttpClient)
    {
        return (OpaAccessControl) OpaAccessControlFactory.create(
                ImmutableMap.<String, String>builder()
                        .put("opa.policy.uri", opaUri.toString())
                        .put("opa.policy.batched-uri", opaBatchUri.toString())
                        .buildOrThrow(),
                Optional.of(mockHttpClient),
                Optional.of(SYSTEM_ACCESS_CONTROL_CONTEXT));
    }

    public static void assertAccessControlMethodThrowsForIllegalResponses(Consumer<OpaAccessControl> methodToTest)
    {
        runIllegalResponseTestCases(methodToTest, TestHelpers::buildAuthorizerWithPredefinedResponse);
    }

    public static void assertBatchAccessControlMethodThrowsForIllegalResponses(Consumer<OpaAccessControl> methodToTest)
    {
        runIllegalResponseTestCases(methodToTest, TestHelpers::buildBatchAuthorizerWithPredefinedResponse);
    }

    private static void runIllegalResponseTestCases(
            Consumer<OpaAccessControl> methodToTest,
            Function<MockResponse, OpaAccessControl> authorizerBuilder)
    {
        assertAccessControlMethodThrows(() -> methodToTest.accept(authorizerBuilder.apply(UNDEFINED_RESPONSE)), OpaQueryException.OpaServerError.PolicyNotFound.class, "did not return a value");
        assertAccessControlMethodThrows(() -> methodToTest.accept(authorizerBuilder.apply(BAD_REQUEST_RESPONSE)), OpaQueryException.OpaServerError.class, "returned status 400");
        assertAccessControlMethodThrows(() -> methodToTest.accept(authorizerBuilder.apply(SERVER_ERROR_RESPONSE)), OpaQueryException.OpaServerError.class, "returned status 500");
        assertAccessControlMethodThrows(() -> methodToTest.accept(authorizerBuilder.apply(MALFORMED_RESPONSE)), OpaQueryException.class, "Failed to deserialize");
    }

    private static OpaAccessControl buildAuthorizerWithPredefinedResponse(MockResponse response)
    {
        return createOpaAuthorizer(OPA_SERVER_URI, createMockHttpClient(OPA_SERVER_URI, request -> response));
    }

    public static OpaAccessControl buildBatchAuthorizerWithPredefinedResponse(MockResponse response)
    {
        return createOpaAuthorizer(OPA_SERVER_URI, OPA_SERVER_BATCH_URI, createMockHttpClient(OPA_SERVER_BATCH_URI, request -> response));
    }

    public static void assertAccessControlMethodThrows(
            Runnable methodToTest,
            Class<? extends OpaQueryException> expectedException,
            String expectedErrorMessage)
    {
        assertThatThrownBy(methodToTest::run)
                .isInstanceOf(expectedException)
                .hasMessageContaining(expectedErrorMessage);
    }

    static final class TestingSystemAccessControlContext
        implements SystemAccessControlFactory.SystemAccessControlContext
    {
        private final String trinoVersion;

        public TestingSystemAccessControlContext(String version)
        {
            this.trinoVersion = version;
        }

        @Override
        public String getVersion()
        {
            return this.trinoVersion;
        }

        @Override
        public OpenTelemetry getOpenTelemetry()
        {
            return null;
        }

        @Override
        public Tracer getTracer()
        {
            return null;
        }
    }
}
