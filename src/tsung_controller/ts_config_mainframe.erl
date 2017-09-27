-module(ts_config_mainframe).

-export([
    parse_config/2,
    uuid/0
]).

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_mainframe.hrl").

-include("xmerl.hrl").


-define(default_username, <<"test">>).
-define(default_password, <<"secret">>).


parse_config(Element = #xmlElement{name = dyn_variable}, Conf = #config{}) ->
    ts_config:parse(Element, Conf);

parse_config(Element = #xmlElement{name = mainframe},
             Config = #config{curid = Id, session_tab = Tab,
                              sessions = [CurS | _], dynvar = DynVar,
                              subst = SubstFlag, match = MatchRegExp}) ->
    Type = xml_attrib(atom, Element, type),
    Request = build_request(Type, Element),


    Msg = #ts_request{
        ack = parse,
        endpage = true,
        dynvar_specs = DynVar,
        subst = SubstFlag,
        match = MatchRegExp,
        param = Request
    },

    ts_config:mark_prev_req(Id - 1, Tab, CurS),
    ets:insert(Tab, {{CurS#session.id, Id}, Msg}),
    lists:foldl(fun(A, B)-> ts_config:parse(A, B) end,
                Config#config{dynvar = []},
                Element#xmlElement.content);

parse_config(Element = #xmlElement{}, Conf = #config{}) ->
    ts_config:parse(Element, Conf);

parse_config(_Data, Conf = #config{}) ->
    Conf.


uuid() ->
    base64:encode(crypto:strong_rand_bytes(16)).


build_request(connect, Element) ->
    ClientId = xml_attrib(binary, Element, client_id, uuid()),
    #mainframe_connect{client_id = ClientId};

build_request(login, Element) ->
    Username = xml_attrib(binary, Element, username, ?default_username),
    Password = xml_attrib(binary, Element, password, ?default_password),
    Payload = #mainframe_login{username = Username, password = Password},
    #mainframe_request{id = uuid(), name = <<"login">>, payload = Payload};

build_request(perform, Element) ->
    Vars = parse_variables(Element),
    {Name, Query} = parse_query(Element),
    Payload = #mainframe_perform{operation_name = Name,
                                 query = Query,
                                 variables = Vars},
    #mainframe_request{id = uuid(), name = <<"graphql.perform">>, payload = Payload};

build_request(close, _Element) ->
    #mainframe_close{}.


parse_variables(Element) ->
    case xml_child(Element, variables, null) of
      null -> [];
      #xmlElement{content = Content} ->
        [{N, V} || {ok, N, V} <- [parse_variables_item(E) || E <- Content]]
    end.


parse_variables_item(Element) ->
  case parse_variables_value(Element) of
    {ok, V} -> {ok, xml_attrib(binary, Element, name), V};
    Other -> Other
  end.


parse_variables_value(#xmlText{}) -> ignore;

parse_variables_value(Element = #xmlElement{name = number}) ->
    {ok, xml_text(integer, Element)};

parse_variables_value(Element = #xmlElement{name = boolean}) ->
    {ok, xml_text(boolean, Element)};

parse_variables_value(Element = #xmlElement{name = string}) ->
    {ok, xml_text(binary, Element)};

parse_variables_value(Element = #xmlElement{name = list, content = Content}) ->
    {ok, [V || {ok, V} <- [parse_variables_value(E) || E <- Content]]};

parse_variables_value(Element = #xmlElement{name = object, content = Content}) ->
    {ok, [{V, N} || {ok, V, N} <- [parse_variables_item(E) || E <- Content]]};

parse_variables_value(Element = #xmlElement{name = null}) ->
    {ok, null}.


parse_query(Element) ->
    QueryElem = xml_child(Element, query),
    Name = xml_attrib(binary, QueryElem, name),
    Query = xml_text(binary, QueryElem),
    Cleaned = re:replace(Query, "\n +", "\n", [global, {return, binary}]),
    {Name, Cleaned}.


xml_value(string, Value) -> Value;

xml_value(list, Value) -> Value;

xml_value(binary, Value) -> list_to_binary(Value);

xml_value(boolean, "true") -> true;

xml_value(boolean, "false") -> false;

xml_value(float_or_integer, Value)->
    case erl_scan:string(Value) of
      {ok, [{integer, _, I}],_} -> I;
      {ok, [{float, _, F}],_} -> F
    end;

xml_value(integer_or_string, Value)->
    case erl_scan:string(Value) of
        {ok, [{integer, _, I}], _} -> I;
        _ -> Value
    end;

xml_value(Type, Value) ->
    {ok, [{Type, _, Val}], _} = erl_scan:string(Value),
    Val.


xml_attrib(Type, #xmlElement{attributes = Attribs}, Name) ->
  xml_attrib(Type, Attribs, Name);

xml_attrib(Type, [#xmlAttribute{name = Name, value = Value} | _], Name) ->
  xml_value(Type, Value);

xml_attrib(Type, [_ | Rest], Name) ->
  xml_attrib(Type, Rest, Name);

xml_attrib(Type, [], Name) ->
  throw({missing_attribute, Name}).


xml_attrib(Type, #xmlElement{attributes = Attribs}, Name, Default) ->
  xml_attrib(Type, Attribs, Name, Default);

xml_attrib(Type, [#xmlAttribute{name = Name, value = Value} | _], Name, _Default) ->
  xml_value(Type, Value);

xml_attrib(Type, [_ | Rest], Name, Default) ->
  xml_attrib(Type, Rest, Name, Default);

xml_attrib(Type, [], Name, Default) ->
  Default.


xml_text(Type, #xmlElement{content = Content}) ->
  xml_text(Type, Content);

xml_text(Type, [#xmlText{value = Value} | _]) ->
  xml_value(Type, string:trim(Value, both, "\n\t ")).


xml_child(#xmlElement{content = Content}, Name) -> xml_child(Content, Name);

xml_child([Element = #xmlElement{name = Name} | _], Name) -> Element;

xml_child([_ | Rest], Name) -> xml_child(Rest, Name);

xml_child([], Name) -> throw({missing_element, Name}).


xml_child(#xmlElement{content = Content}, Name, Default) ->
  xml_child(Content, Name, Default);

xml_child([Element = #xmlElement{name = Name} | _], Name, _Default) -> Element;

xml_child([_ | Rest], Name, Default) -> xml_child(Rest, Name, Default);

xml_child([], Name, Default) -> Default.


