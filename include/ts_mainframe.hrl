-record(mainframe_connect, {
    client_id,
    dummy % Tsung has a bug when there is a single field
}).

-record(mainframe_request, {
    id,
    name,
    payload
}).

-record(mainframe_close, {}).

-record(mainframe_session, {
    status,
    accept
}).

-record(mainframe_login, {
    username,
    password
}).

-record(mainframe_graphql, {
    type,
    name,
    variables,
    graphql,
    version
}).

-record(mainframe_value, {
    type = null,
    ready = true,
    post = undefined,
    value = null
}).


-define(VALUE(V), ts_config_mainframe:value(V)).
-define(SUBST(V, D), ts_config_mainframe:subst(V, D)).
-define(MV, #mainframe_value).