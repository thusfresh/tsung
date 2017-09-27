-module(ts_mainframe).

-behavior(ts_plugin).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_mainframe.hrl").

-export([add_dynparams/4,
  get_message/2,
  session_defaults/0,
  parse/2,
  dump/2,
  parse_bidi/2,
  parse_config/2,
  decode_buffer/2,
  new_session/0]
).


-define(OP_CONT, 0).
-define(OP_TEXT, 1).
-define(OP_BIN, 2).
-define(OP_CLOSE, 8).
-define(OP_PING, 9).
-define(OP_PONG, 10).

-define(WS_PATH, "/api/ws?client_id=~s&client_version=1.13.2&os_version=4.4.0-94-generic&platform=linux&protocol_version=9&utc_offset=-120").


session_defaults() ->
    {ok, true, true}.


decode_buffer(Buffer, Sess) ->
    ?LOGF("MMMMMMMMMM ts_mainframe:decode_buffer(Buffer, Sess)~nBuffer: ~p~nSess: ~p", [Buffer, Sess], ?INFO),
    case websocket:decode(Buffer) of
      more -> <<>>;
      {_Opcode, Payload, _Rest} ->
        ?LOGF(">>>>>>>>>> ts_mainframe:decode_buffer~nPayload: ~p", [Payload], ?INFO),
        Payload
    end.


new_session() ->
    #mainframe_session{}.


dump(A, B) ->
    ts_plugin:dump(A, B).


get_message(#mainframe_connect{client_id = ClientId},
            #state_rcv{session = Sess, host = Host}) ->
    Path = websocket_path(ClientId),
    {Msg, Accept} = websocket:get_handshake(Host, Path, "", "13", ""),
    {Msg, Sess#mainframe_session{status = waiting_handshake,
    accept = Accept}};

get_message(#mainframe_request{id = Id, name = Name, payload = Payload},
            #state_rcv{session = Sess})
  when Sess#mainframe_session.status == connected ->
    Msg = prepare_request(Id, Name, Payload),
    ?DebugF("Mainframe websocket sending: ~p ~p~n", [?OP_TEXT, Msg]),
    Frame = websocket:encode_text(Msg),
    {Frame, Sess};

get_message(#mainframe_close{}, #state_rcv{session = Sess})
  when Sess#mainframe_session.status == connected ->
    {websocket:encode_close(<<"close">>), Sess}.


parse(closed, State) ->
    {State#state_rcv{ack_done = true, acc = [], datasize = 0}, [], true};

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
    case websocket:decode(Data) of
      more ->
        ?DebugF("Mainframe websocket receive incomplete frame: ~p~n", [Data]),
        {State#state_rcv{ack_done = false, acc = Data}, [], false};
      {?OP_CLOSE, _Reason, _} ->
        ?DebugF("Mainframe websocket closed by the server: ~p~n", [_Reason]),
        {State#state_rcv{ack_done = true}, [], true};
      {_Opcode, Payload, Left} ->
        ?DebugF("Mainframe websocket received: ~p ~p~n", [_Opcode, Payload]),
        try mochijson2:decode(Payload) of
          Json ->
            case handle_response(Req#ts_request.param, Json) of
              ack ->
                {State#state_rcv{ack_done = true, acc = Left}, [], false};
              ignore ->
                {State#state_rcv{ack_done = false, acc = Left}, [], false};
              {error, _Reason} ->
                ?DebugF("Mainframe protocol error received: ~p~n", [_Reason]),
                ts_mon_cache:add({count, mainframe_protocol_error}),
                {State#state_rcv{ack_done = true, acc = Left}, [], true}
            end
        catch
          _:_ ->
            ?Debug("Not a valid JSON packet"),
            {State#state_rcv{ack_done = true, acc = Left}, [], true}
        end
    end;

parse(Data, State=#state_rcv{acc = Acc, datasize = DataSize}) ->
    NewSize = DataSize + size(Data),
    parse(<< Acc/binary, Data/binary >>,
          State#state_rcv{acc = [], datasize = NewSize}).


parse_bidi(Data, State) ->
    ?LOGF("MMMMMMMMMM ts_mainframe:parse_bidi(Data, State)~nData: ~p~nState: ~p", [Data, State], ?INFO),
    Result = ts_plugin:parse_bidi(Data, State),
    ?LOGF(">>>>>>>>>> ts_mainframe:parse_bidi~nResult: ~p", [Result], ?INFO),
    Result.


parse_config(Element, Conf) ->
    ts_config_mainframe:parse_config(Element, Conf).


add_dynparams(true, {DynVars, _S},
              Param = #mainframe_connect{client_id = ClientId},
              _HostData) ->
    NewClientId = ts_search:subst(ClientId, DynVars),
    Param#mainframe_connect{client_id = NewClientId};

add_dynparams(true, {DynVars, _S},
              Param = #mainframe_request{payload = Payload},
              _HostData) ->
    NewPayload = subst_params(Payload, DynVars),
    Param#mainframe_request{payload = NewPayload};

add_dynparams(_Bool, _DynData, Param, _HostData) ->
    Param.


subst_params(Param = #mainframe_login{username = User, password = Pass}, DynVars) ->
  NewUser = ts_search:subst(User, DynVars),
  NewPass = ts_search:subst(Pass, DynVars),
  Param#mainframe_login{username = NewUser, password = NewPass};

subst_params(Param = #mainframe_perform{query = Query, variables = Vars}, DynVars) ->
  NewQuery = ts_search:subst(Query, DynVars),
  NewVars = subst_value(Vars, DynVars),
  Param#mainframe_perform{query = NewQuery, variables = NewVars}.


subst_item({Name, Value}, DynVars) ->
  {Name, subst_value(Value, DynVars)}.


subst_value(Value, DynVars) when is_binary(value) ->
  ts_search:subst(Value, DynVars);

subst_value([{_, _} | _] = Fields, DynVars) ->
  [subst_item(I, DynVars) || I <- Fields];

subst_value([_ | _] = Values, DynVars) ->
  [subst_value(V, DynVars) || V <- Values];

subst_value(Value, _DynVars) -> Value.


websocket_path(ClientId) ->
    EncodedId = http_uri:encode(ClientId),
    iolist_to_binary(io_lib:format(?WS_PATH, [EncodedId])).


format_request(Id, Name, Payload) ->
    Json = [request, Name, Payload, Id],
    iolist_to_binary(mochijson2:encode(Json)).


prepare_request(Id, Name, Params) ->
    Payload = prepare_payload(Params),
    format_request(Id, Name, Payload).


prepare_payload(#mainframe_login{username = User, password = Pass}) ->
    ts_mon_cache:add({count, mainframe_login}),
    [{username, User}, {password, Pass}];

prepare_payload(#mainframe_perform{operation_name = Name, query = Query, variables = Vars}) ->
    ts_mon_cache:add({count, mainframe_graphql_perform}),
    [{operation_name, Name}, {query, Query}, {variables, Vars}].


handle_response(#mainframe_request{id = Id, name = Name},
                [<<"error">>, Name, {struct, Fields}, Id]) ->
    Reason = proplists:get_value(<<"reason">>, Fields, unknown),
    {error, Reason};

handle_response(#mainframe_request{id = Id, name = Name},
                [<<"error">>, Name, _Payload, Id]) ->    
    {error, unknown};

handle_response(#mainframe_request{id = Id, name = Name},
                [<<"response">>, Name, _Payload, Id]) ->
    ack;

handle_response(#mainframe_request{name = CurrName},
                [<<"error">>, GotName, _Payload, _Id]) ->
    ?DebugF("Ignoring Mainframe error for ~p request while waiting for ~p response~n", [GotName, CurrName]),
    ts_mon_cache:add({count, mainframe_ignored_error}),
    ignore;

handle_response(#mainframe_request{name = CurrName},
                [<<"response">>, GotName, _Payload, _Id]) ->
    ?DebugF("Ignoring Mainframe response for ~p request while waiting for ~p response~n", [GotName, CurrName]),
    ts_mon_cache:add({count, mainframe_ignored_response}),
    ignore.
