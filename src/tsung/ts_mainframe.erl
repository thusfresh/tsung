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


get_message(#mainframe_connect{client_id = ClientId},
            #state_rcv{session = Sess, host = Host}) ->
    Path = websocket_path(?VALUE(ClientId)),
    {Msg, Accept} = websocket:get_handshake(Host, Path, "", "13", ""),
    {Msg, Sess#mainframe_session{status = waiting_handshake, accept = Accept}};

get_message(#mainframe_request{id = Id, name = Name, payload = Payload},
            #state_rcv{session = Sess})
  when Sess#mainframe_session.status == connected ->
    Msg = prepare_request(Id, Name, Payload),
    ?DebugF("Mainframe websocket sending: ~p~n", [Msg]),
    {websocket:encode_text(Msg), Sess};

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
    case decode_frame(Data) of
      more ->
        ?DebugF("Mainframe websocket receive incomplete frame: ~p~n", [Data]),
        {State#state_rcv{ack_done = false, acc = Data}, [], false};
      {close, _Reason} ->
        ?DebugF("Mainframe websocket closed by the server: ~p~n", [_Reason]),
        {State#state_rcv{ack_done = true}, [], true};
      {ok, Packet, FrameData, Left} ->
        ?DebugF("Mainframe websocket received: ~p~n", [FrameData]),
        case handle_response(Req#ts_request.param, Packet) of
          ack ->
            {State#state_rcv{ack_done = true, acc = Left}, [], false};
          ignore ->
            {State#state_rcv{ack_done = false, acc = Left}, [], false};
          {error, _Reason} ->
            ?DebugF("Mainframe protocol error received: ~p~n", [_Reason]),
            ts_mon_cache:add({count, mainframe_protocol_error}),
            {State#state_rcv{ack_done = true, acc = Left}, [], true}
        end;
      {error, _Reason, _FrameData, Left} ->
        ?DebugF("Mainframe websocket received: ~p~n", [_FrameData]),
        ?DebugF("Mainframe packet decoding error: ~p~n", [_Reason]),
        {State#state_rcv{ack_done = true, acc = Left}, [], true}
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
    NewClientId = ?SUBST(ClientId, DynVars),
    Param#mainframe_connect{client_id = NewClientId};

add_dynparams(true, {DynVars, _S},
              Param = #mainframe_request{payload = Payload},
              _HostData) ->
    NewPayload = subst_params(Payload, DynVars),
    Param#mainframe_request{payload = NewPayload};

add_dynparams(_Bool, _DynData, Param, _HostData) ->
    Param.


subst_params(Param = #mainframe_login{username = User, password = Pass}, DynVars) ->
    NewUser = ?SUBST(User, DynVars),
    NewPass = ?SUBST(Pass, DynVars),
    Param#mainframe_login{username = NewUser, password = NewPass};

subst_params(Param = #mainframe_perform{query = Query, variables = Vars}, DynVars) ->
    NewQuery = ?SUBST(Query, DynVars),
    NewVars = ?SUBST(Vars, DynVars),
    Param#mainframe_perform{query = NewQuery, variables = NewVars}.


websocket_path(ClientId) ->
    EncodedId = http_uri:encode(ClientId),
    iolist_to_binary(io_lib:format(?WS_PATH, [EncodedId])).


decode_frame(Data) ->
    case websocket:decode(Data) of
      more -> more;
      {?OP_CLOSE, Reason, _} -> {close, Reason};
      {_Opcode, FrameData, Left} ->
        case decode_packet(FrameData) of
          {ok, Packet} -> {ok, Packet, FrameData, Left};
          {error, Reason} -> {error, Reason, FrameData, Left}
        end
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


prepare_request(Id, Name, Params) ->
    Payload = prepare_payload(Params),
    format_request(Id, Name, Payload).


prepare_payload(#mainframe_login{username = User, password = Pass}) ->
    ts_mon_cache:add({count, mainframe_login}),
    [{username, ?VALUE(User)}, {password, ?VALUE(Pass)}];

prepare_payload(#mainframe_perform{operation_name = Name, query = Query, variables = Vars}) ->
    ts_mon_cache:add({count, mainframe_graphql_perform}),
    [{operation_name, ?VALUE(Name)},
     {query, ?VALUE(Query)},
     {variables, ?VALUE(Vars)}].


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
