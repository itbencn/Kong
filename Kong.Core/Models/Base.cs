using System;
using System.Collections.Generic;
using System.Text;

namespace Kong.Core.Models
{
    public class RootResponse
    {
        public Timers timers { get; set; }
        public Plugins plugins { get; set; }
        public string lua_version { get; set; }
        public string node_id { get; set; }
        public string version { get; set; }
        public Pids pids { get; set; }
        public Configuration configuration { get; set; }
        public string hostname { get; set; }
        public string tagline { get; set; }
    }

    public class Timers
    {
        public int pending { get; set; }
        public int running { get; set; }
    }

    public class Plugins
    {
        public object[] enabled_in_cluster { get; set; }
        public Available_On_Server available_on_server { get; set; }
    }

    public class Available_On_Server
    {
        public HttpLog httplog { get; set; }
        public KeyAuth keyauth { get; set; }
        public HmacAuth hmacauth { get; set; }
        public BasicAuth basicauth { get; set; }
        public IpRestriction iprestriction { get; set; }
        public RequestTransformer requesttransformer { get; set; }
        public ResponseTransformer responsetransformer { get; set; }
        public RequestSizeLimiting requestsizelimiting { get; set; }
        public RateLimiting ratelimiting { get; set; }
        public ResponseRatelimiting responseratelimiting { get; set; }
        public Syslog syslog { get; set; }
        public Loggly loggly { get; set; }
        public Datadog datadog { get; set; }
        public LdapAuth ldapauth { get; set; }
        public Statsd statsd { get; set; }
        public BotDetection botdetection { get; set; }
        public AwsLambda awslambda { get; set; }
        public RequestTermination requesttermination { get; set; }
        public Prometheus prometheus { get; set; }
        public ProxyCache proxycache { get; set; }
        public Session session { get; set; }
        public Acme acme { get; set; }
        public GrpcGateway grpcgateway { get; set; }
        public GrpcWeb grpcweb { get; set; }
        public PreFunction prefunction { get; set; }
        public PostFunction postfunction { get; set; }
        public AzureFunctions azurefunctions { get; set; }
        public Zipkin zipkin { get; set; }
        public Opentelemetry opentelemetry { get; set; }
        public Jwt jwt { get; set; }
        public Acl acl { get; set; }
        public CorrelationId correlationid { get; set; }
        public Cors cors { get; set; }
        public Oauth2 oauth2 { get; set; }
        public TcpLog tcplog { get; set; }
        public UdpLog udplog { get; set; }
        public FileLog filelog { get; set; }
    }

    public class HttpLog
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class KeyAuth
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class HmacAuth
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class BasicAuth
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class IpRestriction
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class RequestTransformer
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class ResponseTransformer
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class RequestSizeLimiting
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class RateLimiting
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class ResponseRatelimiting
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Syslog
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Loggly
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Datadog
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class LdapAuth
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Statsd
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class BotDetection
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class AwsLambda
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class RequestTermination
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Prometheus
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class ProxyCache
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Session
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Acme
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class GrpcGateway
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class GrpcWeb
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class PreFunction
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class PostFunction
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class AzureFunctions
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Zipkin
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Opentelemetry
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Jwt
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Acl
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class CorrelationId
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Cors
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Oauth2
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class TcpLog
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class UdpLog
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class FileLog
    {
        public int priority { get; set; }
        public string version { get; set; }
    }

    public class Pids
    {
        public int[] workers { get; set; }
        public int master { get; set; }
    }

    public class Configuration
    {
        public string ssl_dhparam { get; set; }
        public string nginx_http_ssl_dhparam { get; set; }
        public string nginx_stream_ssl_dhparam { get; set; }
        public string ssl_session_tickets { get; set; }
        public string nginx_http_ssl_session_tickets { get; set; }
        public string nginx_stream_ssl_session_tickets { get; set; }
        public string ssl_session_timeout { get; set; }
        public string nginx_http_ssl_session_timeout { get; set; }
        public string nginx_stream_ssl_session_timeout { get; set; }
        public string ssl_session_cache_size { get; set; }
        public string proxy_access_log { get; set; }
        public string proxy_error_log { get; set; }
        public string proxy_stream_access_log { get; set; }
        public string proxy_stream_error_log { get; set; }
        public string admin_access_log { get; set; }
        public string admin_error_log { get; set; }
        public string status_access_log { get; set; }
        public string status_error_log { get; set; }
        public string[] lua_ssl_trusted_certificate { get; set; }
        public int lua_ssl_verify_depth { get; set; }
        public string[] vaults { get; set; }
        public string nginx_http_lua_ssl_protocols { get; set; }
        public string nginx_stream_lua_ssl_protocols { get; set; }
        public int lua_socket_pool_size { get; set; }
        public string cluster_control_plane { get; set; }
        public Proxy_Listeners[] proxy_listeners { get; set; }
        public string cluster_mtls { get; set; }
        public Status_Listeners status_listeners { get; set; }
        public string lua_ssl_trusted_certificate_combined { get; set; }
        public string role { get; set; }
        public int cluster_data_plane_purge_delay { get; set; }
        public string cluster_ocsp { get; set; }
        public string database { get; set; }
        public bool cluster_use_proxy { get; set; }
        public string untrusted_lua { get; set; }
        public string log_level { get; set; }
        public Untrusted_Lua_Sandbox_Environment untrusted_lua_sandbox_environment { get; set; }
        public string lmdb_environment_path { get; set; }
        public string lmdb_map_size { get; set; }
        public string[] opentelemetry_tracing { get; set; }
        public int opentelemetry_tracing_sampling_rate { get; set; }
        public string pg_user { get; set; }
        public bool proxy_server_ssl_verify { get; set; }
        public bool allow_debug_header { get; set; }
        public string worker_consistency { get; set; }
        public string error_default_type { get; set; }
        public string[] plugins { get; set; }
        public Dns_Resolver dns_resolver { get; set; }
        public string dns_hostsfile { get; set; }
        public int dns_error_ttl { get; set; }
        public int dns_not_found_ttl { get; set; }
        public string ssl_ciphers { get; set; }
        public int dns_stale_ttl { get; set; }
        public int dns_cache_size { get; set; }
        public string[] db_cache_warmup_entities { get; set; }
        public string[] dns_order { get; set; }
        public bool dns_no_sync { get; set; }
        public string cassandra_keyspace { get; set; }
        public string cassandra_username { get; set; }
        public bool kic { get; set; }
        public Stream_Listeners stream_listeners { get; set; }
        public Ssl_Cert ssl_cert { get; set; }
        public string nginx_stream_ssl_prefer_server_ciphers { get; set; }
        public string admin_acc_logs { get; set; }
        public string nginx_kong_stream_conf { get; set; }
        public string nginx_stream_ssl_protocols { get; set; }
        public string kong_process_secrets { get; set; }
        public Ssl_Cert_Key ssl_cert_key { get; set; }
        public string ssl_protocols { get; set; }
        public string pg_database { get; set; }
        public string prefix { get; set; }
        public bool proxy_ssl_enabled { get; set; }
        public string[] headers { get; set; }
        public string ssl_cert_default { get; set; }
        public int cassandra_schema_consensus_timeout { get; set; }
        public string[] cassandra_data_centers { get; set; }
        public Host_Ports host_ports { get; set; }
        public bool anonymous_reports { get; set; }
        public int cassandra_repl_factor { get; set; }
        public string lua_package_path { get; set; }
        public string kong_env { get; set; }
        public Loaded_Plugins loaded_plugins { get; set; }
        public int cassandra_refresh_frequency { get; set; }
        public string ssl_cipher_suite { get; set; }
        public int cassandra_timeout { get; set; }
        public int pg_timeout { get; set; }
        public Pluginserver_Names pluginserver_names { get; set; }
        public Loaded_Vaults loaded_vaults { get; set; }
        public string ssl_cert_default_ecdsa { get; set; }
        public string router_flavor { get; set; }
        public string ssl_cert_key_default_ecdsa { get; set; }
        public bool legacy_worker_events { get; set; }
        public string client_ssl_cert_default { get; set; }
        public string client_ssl_cert_key_default { get; set; }
        public string admin_ssl_cert_default { get; set; }
        public int upstream_keepalive_pool_size { get; set; }
        public string admin_ssl_cert_key_default { get; set; }
        public Admin_Listeners[] admin_listeners { get; set; }
        public string admin_ssl_cert_default_ecdsa { get; set; }
        public Enabled_Headers enabled_headers { get; set; }
        public string admin_ssl_cert_key_default_ecdsa { get; set; }
        public string cassandra_lb_policy { get; set; }
        public string status_ssl_cert_default { get; set; }
        public int db_update_frequency { get; set; }
        public string status_ssl_cert_key_default { get; set; }
        public int db_update_propagation { get; set; }
        public string status_ssl_cert_default_ecdsa { get; set; }
        public int db_cache_ttl { get; set; }
        public string status_ssl_cert_key_default_ecdsa { get; set; }
        public bool pg_ro_ssl { get; set; }
        public Cluster_Listeners[] cluster_listeners { get; set; }
        public bool client_ssl { get; set; }
        public Port_Maps port_maps { get; set; }
        public string[] proxy_listen { get; set; }
        public string[] admin_listen { get; set; }
        public string[] status_listen { get; set; }
        public string[] stream_listen { get; set; }
        public string[] cluster_listen { get; set; }
        public Admin_Ssl_Cert admin_ssl_cert { get; set; }
        public Admin_Ssl_Cert_Key admin_ssl_cert_key { get; set; }
        public Status_Ssl_Cert status_ssl_cert { get; set; }
        public Status_Ssl_Cert_Key status_ssl_cert_key { get; set; }
        public int db_resurrect_ttl { get; set; }
        public string nginx_user { get; set; }
        public string nginx_main_user { get; set; }
        public string nginx_daemon { get; set; }
        public string lua_ssl_protocols { get; set; }
        public string nginx_main_daemon { get; set; }
        public string nginx_worker_processes { get; set; }
        public string nginx_main_worker_processes { get; set; }
        public Trusted_Ips trusted_ips { get; set; }
        public string real_ip_header { get; set; }
        public string nginx_proxy_real_ip_header { get; set; }
        public string real_ip_recursive { get; set; }
        public string nginx_proxy_real_ip_recursive { get; set; }
        public int pg_port { get; set; }
        public string pg_password { get; set; }
        public bool pg_ssl { get; set; }
        public bool pg_ssl_verify { get; set; }
        public int pg_max_concurrent_queries { get; set; }
        public int pg_semaphore_timeout { get; set; }
        public string pg_host { get; set; }
        public string nginx_http_client_body_buffer_size { get; set; }
        public Untrusted_Lua_Sandbox_Requires untrusted_lua_sandbox_requires { get; set; }
        public string nginx_http_client_max_body_size { get; set; }
        public int upstream_keepalive_idle_timeout { get; set; }
        public bool stream_proxy_ssl_enabled { get; set; }
        public bool admin_ssl_enabled { get; set; }
        public bool status_ssl_enabled { get; set; }
        public string lua_package_cpath { get; set; }
        public string nginx_events_multi_accept { get; set; }
        public string cassandra_write_consistency { get; set; }
        public bool cassandra_ssl_verify { get; set; }
        public string nginx_main_worker_rlimit_nofile { get; set; }
        public string[] tracing_instrumentations { get; set; }
        public string nginx_events_worker_connections { get; set; }
        public int tracing_sampling_rate { get; set; }
        public bool cassandra_ssl { get; set; }
        public string nginx_http_lua_regex_cache_max_entries { get; set; }
        public Nginx_Main_Directives[] nginx_main_directives { get; set; }
        public string mem_cache_size { get; set; }
        public int cassandra_port { get; set; }
        public Nginx_Events_Directives[] nginx_events_directives { get; set; }
        public string[] cassandra_contact_points { get; set; }
        public Nginx_Http_Directives[] nginx_http_directives { get; set; }
        public int worker_state_update_frequency { get; set; }
        public string client_body_buffer_size { get; set; }
        public bool pg_ro_ssl_verify { get; set; }
        public string cassandra_read_consistency { get; set; }
        public Nginx_Upstream_Directives nginx_upstream_directives { get; set; }
        public int upstream_keepalive_max_requests { get; set; }
        public Nginx_Proxy_Directives[] nginx_proxy_directives { get; set; }
        public string nginx_http_charset { get; set; }
        public Nginx_Status_Directives nginx_status_directives { get; set; }
        public string ssl_cert_csr_default { get; set; }
        public Nginx_Admin_Directives[] nginx_admin_directives { get; set; }
        public string cassandra_repl_strategy { get; set; }
        public Nginx_Stream_Directives[] nginx_stream_directives { get; set; }
        public string nginx_conf { get; set; }
        public Nginx_Supstream_Directives nginx_supstream_directives { get; set; }
        public string nginx_admin_client_max_body_size { get; set; }
        public Nginx_Sproxy_Directives nginx_sproxy_directives { get; set; }
        public string nginx_admin_client_body_buffer_size { get; set; }
        public string nginx_kong_conf { get; set; }
        public string nginx_http_lua_regex_match_limit { get; set; }
        public string ssl_cert_key_default { get; set; }
        public string nginx_pid { get; set; }
        public int cluster_max_payload { get; set; }
        public string nginx_http_ssl_protocols { get; set; }
        public string nginx_err_logs { get; set; }
        public string ssl_prefer_server_ciphers { get; set; }
        public string nginx_http_ssl_prefer_server_ciphers { get; set; }
        public string nginx_acc_logs { get; set; }
    }

    public class Status_Listeners
    {
    }

    public class Untrusted_Lua_Sandbox_Environment
    {
    }

    public class Dns_Resolver
    {
    }

    public class Stream_Listeners
    {
    }

    public class Ssl_Cert
    {
    }

    public class Ssl_Cert_Key
    {
    }

    public class Host_Ports
    {
    }

    public class Loaded_Plugins
    {
        public bool httplog { get; set; }
        public bool keyauth { get; set; }
        public bool hmacauth { get; set; }
        public bool basicauth { get; set; }
        public bool iprestriction { get; set; }
        public bool requesttransformer { get; set; }
        public bool responsetransformer { get; set; }
        public bool requestsizelimiting { get; set; }
        public bool ratelimiting { get; set; }
        public bool responseratelimiting { get; set; }
        public bool syslog { get; set; }
        public bool loggly { get; set; }
        public bool datadog { get; set; }
        public bool ldapauth { get; set; }
        public bool statsd { get; set; }
        public bool botdetection { get; set; }
        public bool awslambda { get; set; }
        public bool requesttermination { get; set; }
        public bool prometheus { get; set; }
        public bool proxycache { get; set; }
        public bool session { get; set; }
        public bool acme { get; set; }
        public bool grpcgateway { get; set; }
        public bool grpcweb { get; set; }
        public bool prefunction { get; set; }
        public bool postfunction { get; set; }
        public bool azurefunctions { get; set; }
        public bool zipkin { get; set; }
        public bool opentelemetry { get; set; }
        public bool jwt { get; set; }
        public bool acl { get; set; }
        public bool correlationid { get; set; }
        public bool cors { get; set; }
        public bool oauth2 { get; set; }
        public bool tcplog { get; set; }
        public bool udplog { get; set; }
        public bool filelog { get; set; }
    }

    public class Pluginserver_Names
    {
    }

    public class Loaded_Vaults
    {
        public bool env { get; set; }
    }

    public class Enabled_Headers
    {
        public bool XKongUpstreamLatency { get; set; }
        public bool XKongUpstreamStatus { get; set; }
        public bool Server { get; set; }
        public bool server_tokens { get; set; }
        public bool latency_tokens { get; set; }
        public bool Via { get; set; }
        public bool XKongResponseLatency { get; set; }
        public bool XKongAdminLatency { get; set; }
        public bool XKongProxyLatency { get; set; }
    }

    public class Port_Maps
    {
    }

    public class Admin_Ssl_Cert
    {
    }

    public class Admin_Ssl_Cert_Key
    {
    }

    public class Status_Ssl_Cert
    {
    }

    public class Status_Ssl_Cert_Key
    {
    }

    public class Trusted_Ips
    {
    }

    public class Untrusted_Lua_Sandbox_Requires
    {
    }

    public class Nginx_Upstream_Directives
    {
    }

    public class Nginx_Status_Directives
    {
    }

    public class Nginx_Supstream_Directives
    {
    }

    public class Nginx_Sproxy_Directives
    {
    }

    public class Proxy_Listeners
    {
        public bool bind { get; set; }
        public bool http2 { get; set; }
        public bool proxy_protocol { get; set; }
        public bool deferred { get; set; }
        public bool reuseport { get; set; }
        public bool backlogd { get; set; }
        public bool ipv6onlyon { get; set; }
        public bool ipv6onlyoff { get; set; }
        public bool so_keepaliveon { get; set; }
        public bool so_keepaliveoff { get; set; }
        public bool so_keepalivewwd { get; set; }
        public string listener { get; set; }
        public bool ssl { get; set; }
        public int port { get; set; }
        public string ip { get; set; }
    }

    public class Admin_Listeners
    {
        public bool bind { get; set; }
        public bool http2 { get; set; }
        public bool proxy_protocol { get; set; }
        public bool deferred { get; set; }
        public bool reuseport { get; set; }
        public bool backlogd { get; set; }
        public bool ipv6onlyon { get; set; }
        public bool ipv6onlyoff { get; set; }
        public bool so_keepaliveon { get; set; }
        public bool so_keepaliveoff { get; set; }
        public bool so_keepalivewwd { get; set; }
        public string listener { get; set; }
        public bool ssl { get; set; }
        public int port { get; set; }
        public string ip { get; set; }
    }

    public class Cluster_Listeners
    {
        public bool bind { get; set; }
        public bool http2 { get; set; }
        public bool proxy_protocol { get; set; }
        public bool deferred { get; set; }
        public bool reuseport { get; set; }
        public bool backlogd { get; set; }
        public bool ipv6onlyon { get; set; }
        public bool ipv6onlyoff { get; set; }
        public bool so_keepaliveon { get; set; }
        public bool so_keepaliveoff { get; set; }
        public bool so_keepalivewwd { get; set; }
        public string listener { get; set; }
        public bool ssl { get; set; }
        public int port { get; set; }
        public string ip { get; set; }
    }

    public class Nginx_Main_Directives
    {
        public string name { get; set; }
        public string value { get; set; }
    }

    public class Nginx_Events_Directives
    {
        public string name { get; set; }
        public string value { get; set; }
    }

    public class Nginx_Http_Directives
    {
        public string name { get; set; }
        public string value { get; set; }
    }

    public class Nginx_Proxy_Directives
    {
        public string name { get; set; }
        public string value { get; set; }
    }

    public class Nginx_Admin_Directives
    {
        public string name { get; set; }
        public string value { get; set; }
    }

    public class Nginx_Stream_Directives
    {
        public string name { get; set; }
        public string value { get; set; }
    }

}
