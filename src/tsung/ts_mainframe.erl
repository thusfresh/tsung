-module(ts_mainframe).

-behavior(ts_plugin).


%==============================================================================
% Includes
%==============================================================================

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_mainframe.hrl").


%==============================================================================
% Exports
%==============================================================================

% Tsung Configuration Callback Functions
-export([
  uuid/1
]).

% Behaviour ts_plugin Functions
-export([
  add_dynparams/4,
  get_message/2,
  session_defaults/0,
  parse/2,
  dump/2,
  parse_bidi/2,
  parse_config/2,
  decode_buffer/2,
  new_session/0]
).


%==============================================================================
% Macros and Constants
%==============================================================================

-define(OP_CONT, 0).
-define(OP_TEXT, 1).
-define(OP_BIN, 2).
-define(OP_CLOSE, 8).
-define(OP_PING, 9).
-define(OP_PONG, 10).

-define(WS_PATH, "/api/ws?client_id=~s&client_version=1.13.2&os_version=4.4.0-94-generic&platform=linux&protocol_version=9&utc_offset=-120").


%==============================================================================
% Tsung Configuration Callback Functions
%==============================================================================

uuid(_) -> binary_to_list(ts_config_mainframe:uuid()).



%==============================================================================
% Behaviour ts_plugin Functions
%==============================================================================

session_defaults() ->
    {ok, true, true}.


decode_buffer(Buffer, _Sess) ->
    case decode_frame(Buffer) of
      {ok, Packet, _, _} ->
        Payload = extract_payload(Packet),
        % Tsung do not support pre-decoded JSON :/
        iolist_to_binary(mochijson2:encode(Payload));
      _ -> <<>>
    end.


new_session() ->
    #mainframe_session{}.


dump(A, B) ->
    ts_plugin:dump(A, B).


get_message(#mainframe_connect{client_id = ClientId} = Req,
            #state_rcv{session = Sess, host = Host}) ->
    NewSess = update_metrics(Req, Sess),
    Path = websocket_path(?VALUE(ClientId)),
    {Msg, Accept} = websocket:get_handshake(Host, Path, "", "13", ""),
    {Msg, NewSess#mainframe_session{status = waiting_handshake, accept = Accept}};

get_message(#mainframe_request{id = Id, name = Name, payload = Payload} = Req,
            #state_rcv{session = Sess})
  when Sess#mainframe_session.status == connected ->
    NewSess = update_metrics(Req, Sess),
    Msg = prepare_request(Id, Name, Payload),
    ?DebugF("Mainframe websocket sending:~n~s~n", [Msg]),
    {websocket:encode_text(Msg), NewSess};

get_message(#mainframe_close{} = Req, #state_rcv{session = Sess})
  when Sess#mainframe_session.status == connected ->
    NewSess = update_metrics(Req, Sess),
    {websocket:encode_close(<<"close">>), NewSess}.


parse(closed, State) ->
    {State#state_rcv{count = 0, ack_done = true, acc = [], datasize = 0}, [], true};

parse(Data, State = #state_rcv{acc = [], datasize = 0}) ->
    parse(Data, State#state_rcv{datasize = size(Data)});

parse(Data, State = #state_rcv{acc = [], session = Sess})
  when Sess#mainframe_session.status == waiting_handshake ->
    Accept = Sess#mainframe_session.accept,
    case websocket:check_handshake(Data, Accept) of
      ok ->
        ?Debug("Mainframe websocket handshake succeed~n"),
        ts_mon_cache:add({count, mainframe_connect_succeed}),
        Sess2 = Sess#mainframe_session{status = connected},
        State2 = State#state_rcv{ack_done = true, session = Sess2},
        {State2, [], false};
      {error, _Reason} ->
        ?DebugF("Mainframe websocket handshake failed: ~p~n", [_Reason]),
        ts_mon_cache:add({count, mainframe_connect_failed}),
        {State#state_rcv{ack_done = true}, [], true}
    end;

parse(Data, State = #state_rcv{acc = [], session = Sess, request = Req})
  when Sess#mainframe_session.status == connected ->
    case decode_frame(Data) of
      more ->
        ?DebugF("Mainframe websocket receive incomplete frame:~n~s~n", [Data]),
        {State#state_rcv{ack_done = false, acc = Data}, [], false};
      {close, _Reason} ->
        ?LOGF("Mainframe websocket closed by the server: ~p~n", [_Reason], ?WARN),
        ts_mon_cache:add({count, mainframe_server_close}),
        {State#state_rcv{count = 0, ack_done = true}, [], true};
      {ok, Packet, FrameData, Left} ->
        ?DebugF("Mainframe websocket received:~n~s~n", [FrameData]),
        case handle_response(Req#ts_request.param, Packet) of
          ack ->
            {State#state_rcv{ack_done = true, acc = Left}, [], false};
          ignore ->
            {State#state_rcv{ack_done = false, acc = Left}, [], false};
          {error, _Reason} ->
            {State#state_rcv{count = 0, ack_done = true, acc = Left}, [], true}
        end;
      {error, _Reason, _FrameData, Left} ->
        ?DebugF("Mainframe websocket received:~n~s~n", [_FrameData]),
        ?LOGF("Mainframe packet decoding error:~n~p~n", [_Reason], ?WARN),
        ts_mon_cache:add({count, mainframe_decoding_error}),
        {State#state_rcv{count = 0, ack_done = true, acc = Left}, [], true}
    end;

parse(Data, State=#state_rcv{acc = Acc, datasize = DataSize}) ->
    NewSize = DataSize + size(Data),
    parse(<< Acc/binary, Data/binary >>,
          State#state_rcv{acc = [], datasize = NewSize}).


parse_bidi(Data, State = #state_rcv{acc = [], session = Sess, request = Req})
  when Sess#mainframe_session.status == connected ->
    case decode_frame(Data) of
      more ->
        ?DebugF("(bidi) Mainframe websocket receive incomplete frame:~n~s~n", [Data]),
        {nodata, State#state_rcv{acc = Data}, think};
      {close, _Reason} ->
        ?LOGF("(bidi) Mainframe websocket closed by the server: ~p~n", [_Reason], ?WARN),
        ts_mon_cache:add({count, mainframe_server_close}),
        % Tsung do not really support errors for bidi
        {nodata, State#state_rcv{count = 0}, continue};
      {ok, Packet, FrameData, Left} ->
        ?DebugF("(bidi) Mainframe websocket received:~n~s~n", [FrameData]),
        case handle_bidi(Sess, Packet) of
          {ignore, NewSess} ->
            {nodata, State#state_rcv{acc = Left, session = NewSess}, think};
          {error, _Reason} ->
            % Tsung do not really support errors for bidi
            {nodata, State#state_rcv{count = 0, acc = Left}, continue};
          {think, Data, NewSess} ->
            {Data, State#state_rcv{acc = Left, session = NewSess}, think};
          {continue, Data, NewSess} ->
            {Data, State#state_rcv{acc = Left, session = NewSess}, continue}
        end;
      {error, _Reason, _FrameData, Left} ->
        ?DebugF("(bidi) Mainframe websocket received:~n~s~n", [_FrameData]),
        ?LOGF("(bidi) Mainframe packet decoding error: ~p~n", [_Reason], ?WARN),
        ts_mon_cache:add({count, mainframe_decoding_error}),
        {nodata, State#state_rcv{count = 0, acc = Left}, continue}
    end;

parse_bidi(Data, State) -> ts_plugin:parse_bidi(Data, State).


parse_config(Element, Conf) ->
    ts_config_mainframe:parse_config(Element, Conf).


add_dynparams(true, {DynVars, _S},
              Param = #mainframe_connect{client_id = ClientId},
              _HostData) ->
    NewClientId = ?SUBST(ClientId, DynVars),
    Param#mainframe_connect{client_id = NewClientId};

add_dynparams(true, {DynVars, _S},
              Param = #mainframe_request{payload = Payload},
              _HostData) ->
    NewPayload = subst_params(Payload, DynVars),
    Param#mainframe_request{payload = NewPayload};

add_dynparams(_Bool, _DynData, Param, _HostData) ->
    Param.


%==============================================================================
% Internal Functions
%==============================================================================

websocket_path(ClientId) ->
    EncodedId = http_uri:encode(ClientId),
    iolist_to_binary(io_lib:format(?WS_PATH, [EncodedId])).


decode_frame(Data) ->
    case websocket:decode(Data) of
      more -> more;
      {?OP_CLOSE, Reason, _} -> {close, Reason};
      {?OP_TEXT, FrameData, Left} ->
        case decode_packet(FrameData) of
          {ok, Packet} -> {ok, Packet, FrameData, Left};
          {error, Reason} -> {error, Reason, FrameData, Left}
        end;
      {OpCode, _Data, _Rest} ->
        ?LOGF("Unexpected websocket OP code: ~p~n", [OpCode], ?ERR),
        {error, {unexpected_websocekt_opcode, OpCode}}
    end.


decode_packet(Packet) ->
    try mochijson2:decode(Packet) of
      Json -> {ok, Json}
    catch
      _:_ -> {error, bad_json}
    end.


extract_payload([_, _, Payload, _]) -> Payload;

extract_payload([_, _, Payload]) -> Payload;

extract_payload(_) -> <<>>.


format_request(Id, Name, Payload) ->
    Json = [request, Name, Payload, Id],
    iolist_to_binary(mochijson2:encode(Json)).


update_metrics(#mainframe_connect{}, Sess) ->
    ts_mon_cache:add({count, mainframe_connect}),
    Sess;

update_metrics(#mainframe_request{payload = Payload}, Sess) ->
  update_request_metrics(Payload, Sess);

update_metrics(#mainframe_close{}, Sess) ->
    ts_mon_cache:add({count, mainframe_close}),
    Sess.


update_request_metrics(#mainframe_login{}, Sess) ->
    ts_mon_cache:add({count, mainframe_login}),
    Sess;

update_request_metrics(#mainframe_graphql{type = query}, Sess) ->
    ts_mon_cache:add([{count, mainframe_graphql},
                      {count, mainframe_graphql_query}]),
    Sess;

update_request_metrics(#mainframe_graphql{type = mutation}, Sess) ->
    ts_mon_cache:add([{count, mainframe_graphql},
                      {count, mainframe_graphql_mutation}]),
    Sess;

update_request_metrics(#mainframe_graphql{type = subscription}, Sess) ->
    ts_mon_cache:add([{count, mainframe_graphql},
                      {count, mainframe_graphql_subscription}]),
    Sess.


prepare_request(Id, Name, Params) ->
    Payload = prepare_payload(Params),
    format_request(Id, Name, Payload).


subst_params(Param = #mainframe_login{username = User, password = Pass}, DynVars) ->
    NewUser = ?SUBST(User, DynVars),
    NewPass = ?SUBST(Pass, DynVars),
    Param#mainframe_login{username = NewUser, password = NewPass};

subst_params(Param = #mainframe_graphql{name = Name, graphql = Graphql, variables = Vars}, DynVars) ->
    NewName = ?SUBST(Name, DynVars),
    NewGraphql = ?SUBST(Graphql, DynVars),
    NewVars = ?SUBST(Vars, DynVars),
    Param#mainframe_graphql{name = NewName, graphql = NewGraphql, variables = NewVars}.


prepare_payload(#mainframe_login{username = User, password = Pass}) ->
    [{username, ?VALUE(User)}, {password, ?VALUE(Pass)}];

prepare_payload(#mainframe_graphql{name = Name, graphql = Graphql, variables = Vars, version = undefined}) ->
    [{operation_name, ?VALUE(Name)},
     {query, ?VALUE(Graphql)},
     {variables, ?VALUE(Vars)}];

prepare_payload(#mainframe_graphql{name = Name, graphql = Graphql, variables = Vars, version = Ver}) ->
    [{operation_name, ?VALUE(Name)},
     {query, ?VALUE(Graphql)},
     {variables, ?VALUE(Vars)},
     {version, ?VALUE(Ver)}].


handle_response(#mainframe_request{id = Id, name = Name},
                [<<"error">>, Name, {struct, Fields}, Id]) ->
    Reason = proplists:get_value(<<"reason">>, Fields, unknown),
    ts_mon_cache:add({count, mainframe_protocol_error}),
    ?LOGF("Mainframe protocol error received: ~p~n", [Reason], ?ERR),
    {error, protocol_error};

handle_response(#mainframe_request{id = Id, name = Name},
                [<<"error">>, Name, _Payload, Id]) ->
    ts_mon_cache:add({count, mainframe_protocol_error}),
    ?LOG("Unknown Mainframe protocol error received~n", ?ERR),
    {error, protocol_error};

handle_response(#mainframe_request{id = Id, name = Name},
                [<<"response">>, Name, {struct, Fields}, Id])
  when Name =:= <<"graphql.perform">>; Name =:= <<"graphql.subscribe">> ->
    case proplists:get_value(<<"errors">>, Fields) of
      undefined -> ack;
      [] -> ack;
      _Errors ->
        ts_mon_cache:add([{count, mainframe_protocol_error},
                          {count, mainframe_graphql_error}]),
        ?LOGF("Mainframe graphql error(s) received: ~s~n", [extract_graphql_errors(_Errors)], ?ERR),
        {error, graphql_error}
    end;

handle_response(#mainframe_request{id = Id, name = Name},
                [<<"response">>, Name, _Payload, Id]) ->
    ack;

handle_response(#mainframe_request{name = CurrName},
                [<<"error">>, GotName, _Payload, _Id]) ->
    ?LOGF("Ignoring Mainframe error for ~s request while waiting for ~s response~n", [GotName, CurrName], ?ERR),
    ts_mon_cache:add({count, mainframe_ignored_error}),
    ignore;

handle_response(#mainframe_request{name = CurrName},
                [<<"response">>, GotName, _Payload, _Id]) ->
    ?LOGF("Ignoring Mainframe response for ~s request while waiting for ~s response~n", [GotName, CurrName], ?ERR),
    ts_mon_cache:add({count, mainframe_ignored_response}),
    ignore;

handle_response(_Req, [<<"event">>, Name, _Payload]) ->
    ?DebugF("Ignoring Mainframe event ~s~n", [Name]),
    ts_mon_cache:add({count, mainframe_event}),
    ignore;

handle_response(_Req, [<<"alert">>, <<"account_flag_changed">>, _]) -> ignore;

handle_response(_Req, [<<"alert">>, <<"invalid_authentication">>, _]) ->
    ts_mon_cache:add({count, mainframe_authentication_error}),
    ?LOG("Mainframe authentication invalidated (alert)~n", ?ERR),
    {error, authentication_invalidated};

handle_response(#mainframe_request{name = Name}, Packet) ->
    ?LOGF("Received unexpected packet waiting for request ~s response:~n~p~n", [Name, Packet], ?ERR),
    ts_mon_cache:add({count, mainframe_unexpected_packet}),
    {error, unexpected_packet}.


handle_bidi(Sess, [<<"event">>, Name, _Payload]) ->
    ?DebugF("Ignoring Mainframe event ~s~n", [Name]),
    ts_mon_cache:add({count, mainframe_event}),
    {ignore, Sess};

handle_bidi(Sess, [<<"alert">>, <<"account_flag_changed">>, _]) ->
    {ignore, Sess};

handle_bidi(_Sess, [<<"alert">>, <<"invalid_authentication">>, _]) ->
    ts_mon_cache:add({count, mainframe_authentication_error}),
    ?LOG("Mainframe authentication invalidated (alert)~n", ?ERR),
    {error, authentication_invalidated};

handle_bidi(Sess, Packet) ->
    ?LOGF("Received unexpected bidi packet:~n~p~n", [Packet], ?ERR),
    ts_mon_cache:add({count, mainframe_unexpected_bidi_packet}),
    {error, unexpected_bidi_packet}.


extract_graphql_errors(Errors) ->
    Reasons = [proplists:get_value(<<"reason">>, E, <<"unknown">>) || {struct, E} <- Errors],
    join_binaries(Reasons, <<",">>).


join_binaries([], _Sep) -> <<>>;
join_binaries([Part], _Sep) -> Part;
join_binaries(List, Sep) ->
    lists:foldr(fun (A, B) ->
      if
        bit_size(B) > 0 -> <<A/binary, Sep/binary, B/binary>>;
        true -> A
      end
    end, <<>>, List).