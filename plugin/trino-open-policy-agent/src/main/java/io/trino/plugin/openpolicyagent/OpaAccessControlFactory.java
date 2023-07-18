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
package io.trino.plugin.openpolicyagent;

import com.google.common.annotations.VisibleForTesting;
import com.google.inject.Injector;
import com.google.inject.Key;
import io.airlift.bootstrap.Bootstrap;
import io.airlift.http.client.HttpClient;
import io.airlift.json.JsonModule;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.SystemAccessControlFactory;

import java.util.Map;
import java.util.Optional;

import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static io.airlift.json.JsonCodecBinder.jsonCodecBinder;
import static java.util.Objects.requireNonNull;

public class OpaAccessControlFactory
        implements SystemAccessControlFactory
{
    @Override
    public String getName()
    {
        return "opa";
    }

    @Override
    public SystemAccessControl create(Map<String, String> config)
    {
        return create(config, Optional.empty());
    }

    @VisibleForTesting
    protected SystemAccessControl create(Map<String, String> config, Optional<HttpClient> httpClient)
    {
        requireNonNull(config, "config is null");

        Bootstrap app = new Bootstrap(
                new JsonModule(),
                binder -> {
                    jsonCodecBinder(binder).bindJsonCodec(OpaQuery.class);
                    jsonCodecBinder(binder).bindJsonCodec(OpaAccessControl.OpaQueryResult.class);
                    if (httpClient.isEmpty()) {
                        httpClientBinder(binder).bindHttpClient("opa-access-control", ForOpa.class);
                    }
                    else {
                        binder.bind(Key.get(HttpClient.class, ForOpa.class)).toInstance(httpClient.orElseThrow());
                    }
                },
                new OpaAccessControlModule());

        Injector injector = app
                .doNotInitializeLogging()
                .setRequiredConfigurationProperties(config)
                .initialize();
        return injector.getInstance(Key.get(SystemAccessControl.class, ForOpa.class));
    }
}
