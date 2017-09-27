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

-record(mainframe_perform, {
    operation_name,
    variables,
    query
}).
