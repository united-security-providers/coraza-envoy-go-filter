# coraza-envoy-go-filter

* [Coraza](https://github.com/corazawaf/coraza) Web Application Firewall implemented as Envoy Go Filter.

## Getting started

### Running the docker image

Pull and start the image:
```bash
docker pull ghcr.io/united-security-providers/envoy-coraza:v2.0.0
docker run -p 8080:10000 ghcr.io/united-security-providers/envoy-coraza:v2.0.0
```

First visit http://localhost:8080 and then http://localhost:8080/alert('xss').

> [!NOTE]
> The second request should be blocked and you should see `WAF rule triggered: Javascript method detected` in the container logs.

### Running the filter in an Envoy process

In order to run the coraza go filter, we need to spin up an envoy configuration including this as the filter config

```yaml
    ...

    filter_chains:
      - filters:
          - name: envoy.filters.network.http_connection_manager
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
              stat_prefix: ingress_http
              http_filters:
                - name: envoy.filters.http.golang
                  typed_config:
                    "@type": type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config
                    library_id: coraza-waf
                    library_path: /etc/envoy/coraza-waf.so
                    plugin_name: coraza-waf
                    plugin_config:
                      "@type": type.googleapis.com/xds.type.v3.TypedStruct
                      value:
                        directives: |
                          {
                                  "waf1":{
                                        "simple_directives":[
                                              "Include @coraza-lts",
                                              "Include @crs-setup-lts",
                                              "SecDefaultAction \"phase:3,log,auditlog,pass\"",
                                              "SecDefaultAction \"phase:4,log,auditlog,pass\"",
                                              "SecDefaultAction \"phase:5,log,auditlog,pass\"",
                                              "SecDebugLogLevel 3",
                                              "Include @owasp_crs_lts/*.conf",
                                              "SecRule REQUEST_URI \"@streq /admin\" \"id:101,phase:1,t:lowercase,deny\" \nSecRule REQUEST_BODY \"@rx maliciouspayload\" \"id:102,phase:2,t:lowercase,deny\" \nSecRule RESPONSE_HEADERS::status \"@rx 406\" \"id:103,phase:3,t:lowercase,deny\" \nSecRule RESPONSE_BODY \"@contains responsebodycode\" \"id:104,phase:4,t:lowercase,deny\""
                                          ]
                                    },
                                    "off":{
                                      "simple_directives":[
                                        "SecRuleEngine Off"
                                      ]
                                    }
                                }
                        default_directive: "waf1"
                        host_directive_map: |
                          {
                            "foo.example.com":"waf1",
                            "bar.example.com":"off"
                          }
```

### Using with EnvoyGateway

Enable [EnvoyPatchPolicy](https://gateway.envoyproxy.io/docs/tasks/extensibility/envoy-patch-policy/#enable-envoypatchpolicy)
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: envoy-gateway-config
  namespace: envoy-gateway-system
data:
  envoy-gateway.yaml: |
    apiVersion: gateway.envoyproxy.io/v1alpha1
    kind: EnvoyGateway
    provider:
      type: Kubernetes
    gateway:
      controllerName: gateway.envoyproxy.io/gatewayclass-controller
    extensionApis:
      enableEnvoyPatchPolicy: true
```

Update the EnvoyProxy to use the united-security-providers/envoy-coraza image:
```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyProxy
metadata:
  name: eg
  namespace: envoy-gateway-system
spec:
  provider:
    type: Kubernetes
    kubernetes:
      envoyDeployment:
        container:
          image: ghcr.io/united-security-providers/envoy-coraza:v2.0.0
```

Enable the plugin with an EnvoyPatchPolicy:
```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: EnvoyPatchPolicy
metadata:
  name: coraza-patch-policy
  namespace: envoy-gateway-system
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: Gateway
    name: eg-internal
  type: JSONPatch
  jsonPatches:
  - type: "type.googleapis.com/envoy.config.listener.v3.Listener"
    ## The name is in the format <namespace>/<gateway>/<listener> as per the XDS Name Scheme V2 - https://gateway.envoyproxy.io/docs/tasks/extensibility/envoy-patch-policy/#xds-name-scheme-v2
    name: envoy-gateway-system/eg/https
    operation:
      op: add
      ## Needs to be added as the first item in the 'http_filters' array
      path: "/filter_chains/0/filters/0/typed_config/http_filters/0"
      value:
        name: envoy.filters.http.golang
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config
          library_id: coraza-waf
          library_path: /etc/envoy/coraza-waf.so
          plugin_name: coraza-waf
          plugin_config:
            "@type": type.googleapis.com/xds.type.v3.TypedStruct
            value:
              ## setting the logs to json format, so they are the same as the default EnvoyGateway Access Logs
              log_format: "json"
              ## configure coraza/CRS
              directives: |
                {
                  "default":{
                    "simple_directives":[
                      "Include @coraza-lts",
                      "SecDebugLogLevel 9",
                      "SecRuleEngine On",
                      "Include @crs-setup-lts",
                      "Include @owasp_crs_lts/*.conf"
                    ]
                  },
                  "off":{
                    "simple_directives":[
                      "SecRuleEngine Off"
                    ]
                  }
                }
              default_directive: "default"
              host_directive_map: |
                {
                  "foo.example.com":"off",
                  "bar.example.com":"default"
                }
```

### Using CRS

The [Core Rule Set](https://github.com/coreruleset/coreruleset) comes embedded in the extension. 

> [!TIP]
> You can also load a [different CRS version or your own rules from filesystem.](#using-custom-rules-or-load-a-different-crs-version)

Additionally to the rules, configuration files for setting up the rule engine and coraza are embedded as well.
To include embedded rules and config files, the **@** sign is used when referencing a path. 

* [@owasp_crs/*.conf](./internal/config/coreruleset/rules): the CRS rules
* [@coraza-setup](./internal/config/coreruleset/coraza.conf): configures the rule engine for coraza
* [@crs-setup](./internal/config/coreruleset/crs-setup.conf): setup coreruleset

Example loading entire coreruleset:
```yaml
                    plugin_config:
                      "@type": type.googleapis.com/xds.type.v3.TypedStruct
                      value:
                        directives: |
                          {
                                  "waf1":{
                                        "simple_directives":[
                                                "Include @coraza-setup",
                                                "SecDebugLogLevel 9",
                                                "SecRuleEngine On",
                                                "Include @crs-setup",
                                                "Include @owasp_crs/*.conf"
                                          ]
                                    }
                                }
                        default_directive: "waf1"
```

Loading some pieces of the ruleset:
```yaml
                    plugin_config:
                      "@type": type.googleapis.com/xds.type.v3.TypedStruct
                      value:
                        directives: |
                          {
                                  "waf1":{
                                        "simple_directives":[
                                                "Include @coraza-setup",
                                                "SecDebugLogLevel 9",
                                                "SecRuleEngine On",
                                                "Include @crs-setup",
                                                "Include @owasp_crs/REQUEST-901-INITIALIZATION.conf"
                                          ]
                                    }
                                }
                        default_directive: "waf1"
```

#### Recommendations using CRS with Envoy Go

- In order to mitigate as much as possible malicious requests (or connections open) sent upstream, it is recommended to keep the [CRS Early Blocking](https://coreruleset.org/20220302/the-case-for-early-blocking/) feature enabled (SecAction [`900120`](./src/rules/crs-setup.conf.example)).

#### FTW configuration files

If you want to run the ftw test suite (for example in your ci environment), the configuration files are included in the shared object as well:

* [@crs-ftw](./internal/config/coreruleset/crs-ftw.conf): configures rule engine for ftw tests
* [@coraza-ftw](./internal/config/coreruleset/coraza-ftw.conf): configures coraza for ftw tests

### Using custom rules or load a different CRS version

Additionally to the compiled in CRS, filter supports loading rules from filesystem.
This can be useful to load custom rules, blocklists or another CRS version.

#### Custom Rule example
For example to load a file myrule.conf, we can first mount it into the container
```bash
docker run  -v ./envoy.yaml:/etc/envoy/envoy.yaml -v ./myrule.conf:/etc/envoy/myrule.conf ghcr.io/united-security-providers/envoy-coraza:v2.0.0
```
(if you run encoy directly this is of course not needed, simply put it somewhere on the filesystem)

And in the envoy config we can include the file:
```yaml
[...]
plugin_config:
  "@type": type.googleapis.com/xds.type.v3.TypedStruct
  value:
    directives: |
      {
              "waf1":{
                    "simple_directives":[
                            "Include @coraza-latest",
                            "SecDebugLogLevel 9",
                            "SecRuleEngine On",
                            "Include @crs-setup-latest",
                            "Include @owasp_crs_latest/*.conf",
                            "Include /etc/envoy/myrule.conf"
                      ]
                }
            }
    default_directive: "waf1"
[...]
```
*Note the missing @, it means "try to load from filesystem"*

#### Blocklist example
The following example shows how to mount and use blocklist.txt:
```bash
docker run  -v ./envoy.yaml:/etc/envoy/envoy.yaml -v ./blocklist.txt:/etc/envoy/blocklist.txt ghcr.io/united-security-providers/envoy-coraza:v2.0.0
```
And in the envoy config add the rule:
```yaml
[...]
plugin_config:
  "@type": type.googleapis.com/xds.type.v3.TypedStruct
  value:
    directives: |
      {
              "waf1":{
                    "simple_directives":[
                            "Include @coraza-latest",
                            "SecDebugLogLevel 9",
                            "SecRuleEngine On",
                            "Include @crs-setup-latest",
                            "Include @owasp_crs_latest/*.conf",
                            "SecRule REMOTE_ADDR \"@ipMatchFromFile /etc/envoy/blocklist.txt\" \"id:200003,phase:1,deny,status:403,msg:'IP Blocked by Blocklist'\"
                      ]
                }
            }
    default_directive: "waf1"
[...]
```

#### Loading another CRS version example

Example loading CRS 4.22 (assuming you have the rules locally): 
```bash
docker run  -v ./envoy.yaml:/etc/envoy/envoy.yaml -v ./cureruleset-4.22:/etc/envoy/crs-4.22  ghcr.io/united-security-providers/envoy-coraza:v2.0.0
```
And in the envoy config load the ruleset:
```yaml
[...]
plugin_config:
  "@type": type.googleapis.com/xds.type.v3.TypedStruct
  value:
    directives: |
      {
              "waf1":{
                    "simple_directives":[
                            "Include @coraza-latest",
                            "SecDebugLogLevel 9",
                            "SecRuleEngine On",
                            "Include /etc/envoy/crs-4.22/crs-setup.conf.example",
                            "Include /etc/envoy/crs-4.22/*.conf"
                      ]
                }
            }
    default_directive: "waf1"
[...]
```

## Compilation

See [Makefile](./Makefile) for all targets.

### Building the filter

```bash
make build
# or
make performanceBuild
```

You will find the go waf plugin under `./build/coraza-waf.so`.

### Performance

There is [a known performance issue with larger request bodies in Coraza](https://github.com/corazawaf/coraza/issues/1176).
To help mitigate this, a new build target named `performanceBuild` has been introduced.
This target compiles the filter with support for both [re2](https://github.com/google/re2) and
[libinjection](https://github.com/libinjection/libinjection) to improve throughput.
The only downside is that this build introduces runtime dependencies on `re2` and `libinjection`.

You can enable this behavior through the configuration. For example:

```yaml
  ...

  filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          http_filters:
            - name: envoy.filters.http.golang
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.http.golang.v3alpha.Config
                library_id: coraza-waf
                library_path: /etc/envoy/coraza-waf.so
                plugin_name: coraza-waf
                plugin_config:
                  "@type": type.googleapis.com/xds.type.v3.TypedStruct
                  value:
                    use_re2: true
                    use_libinjection: true
```

> [!NOTE]
> Setting these configuration options in the normal build will have no effect on coraza.

## Testing

### Running go-ftw (CRS Regression tests)

The following command runs the [go-ftw](https://github.com/coreruleset/go-ftw) test suite two times against the filter with the CRS lts/latest fully loaded.

```bash
make ftw
```

It's also possible to run tests against a specific CRS version:
```bash
# run ftw tests against lts CRS
make ftw-lts

# run ftw tests against latest CRS
make ftw-latest
```

Take a look at the config files [ftw-lts.yml](./tests/ftw/ftw-lts.yml), [overrides-lts.yml](./tests/ftw/overrides-lts.yml) and [ftw-latest.yml](./tests/ftw/ftw-latest.yml), [overrides-latest.yml](./tests/ftw/overrides-latest.yml) for details about tests currently excluded and overridden.

One can also run a single test by executing:

```bash
FTW_INCLUDE=920410 make ftw
```

Run the tests and abort on the first test that fails:

```bash
FTW_FAILFAST=1 make ftw
```


### Running e2e tests

The following command runs a small set of end to end tests against the filter with the CRS fully loaded.

```bash
make e2e
```

## Log format

By the dafault the filter writes plain text logs.
The log format can be changed to json using the `log_format` configuraion option:
```yaml
                    plugin_config:
                      "@type": type.googleapis.com/xds.type.v3.TypedStruct
                      value:
                        log_format: "json"
                        directives: |
                             [ ... ....  ]
                        default_directive: "waf1"
```

**Note that this setting does not automatically set the AuditLog Engine to JSON**

If an audit log in json is desired, it must be configured with SecLang. For example:
```yaml

                      plugin_config:
                          "@type": type.googleapis.com/xds.type.v3.TypedStruct
                          value:
                              log_format: "json"
                              directives: |
                                {
                                  "waf1":{
                                        "simple_directives":[
                                              [ ..... ]
                                              "SecAuditLog /etc/envoy/logs/audit.log",
                                              "SecAuditLogParts ABCFHKZ",
                                              "SecAuditEngine RelevantOnly",
                                              "SecAuditLogRelevantStatus ^(?:5|4)",
                                              "SecAuditLogFormat JSON",
                                              [ ..... ]
                                        ]
                                    },
                                }
                              default_directive: "waf1"
```
