-module(ts_config_mainframe).

%==============================================================================
% Includes
%==============================================================================

-include("ts_profile.hrl").
-include("ts_config.hrl").
-include("ts_mainframe.hrl").

-include("xmerl.hrl").


%==============================================================================
% Exports
%==============================================================================

-export([
    uuid/0,
    subst/2,
    value/1,
    convert/2,
    parse_config/2
]).


%==============================================================================
% Macros and Constants
%==============================================================================

-define(DEFAULT_USERNAME, <<"test">>).
-define(DEFAULT_PASSWORD, <<"secret">>).
-define(GRAPHQL_QUERY_NAME_RX, "^[ \n\t]*query[ \n\t]*([a-zA-Z][a-zA-Z0-9-_]*)[ \n\t]*\\(").
-define(GRAPHQL_MUTATION_NAME_RX, "^[ \n\t]*mutation[ \n\t]*([a-zA-Z][a-zA-Z0-9-_]*)[ \n\t]*\\(").
-define(GRAPHQL_SUBSCRIPTION_NAME_RX, "^[ \n\t]*subscription[ \n\t]*([a-zA-Z][a-zA-Z0-9-_]*)[ \n\t]*\\(").

-define(MV_NUM(Val), mainframe_value(number, Val)).
-define(MV_STR(Val), mainframe_value(string, Val)).
-define(MV_BOOL(Val), mainframe_value(boolean, Val)).
-define(MV_LIST(Val), mainframe_value(list, Val)).
-define(MV_OBJ(Val), mainframe_value(object, Val)).


%==============================================================================
% API Functions
%==============================================================================

uuid() -> base64:encode(crypto:strong_rand_bytes(16)).


subst(?MV{ready = true} = Spec, _DynVars) -> Spec;

subst(?MV{type = Type, value = Value} = Spec, DynVars)
  when Type =:= string; Type =:= atom; Type =:= number; Type =:= boolean ->
    NewValue = convert(Type, ts_search:subst(Value, DynVars)),
    post_subst(Spec, NewValue);

subst(?MV{type = list, value = Values} = Spec, DynVars) ->
    NewValues = [subst(V, DynVars) || V <- Values],
    post_subst(Spec, NewValues);

subst(?MV{type = object, value = Values} = Spec, DynVars) ->
    NewValues = [{subst(N, DynVars), subst(V, DynVars)} || {N, V} <- Values],
    post_subst(Spec, NewValues);

subst(?MV{} = Spec, _DynVars) -> throw({invalid_value_spec, Spec});

subst(Value, _DynVars) -> Value.


value(?MV{ready = false, value = Value}) ->
    throw({value_needs_substitution, Value});

value(?MV{type = Type, value = Value})
  when Type =:= string; Type =:= atom; Type =:= number; Type =:= boolean; Type =:= null ->
    Value;

value(?MV{type = list, value = Values}) ->
  [value(V) || V <- Values];

value(?MV{type = object, value = Values}) ->
  [{value(N), value(V)} || {N, V} <- Values];

value(?MV{} = Spec) -> throw({invalid_value_spec, Spec});

value(Value) -> Value.


convert(string, Value) when is_list(Value) -> list_to_binary(Value);

convert(string, Value) when is_binary(Value) -> Value;

convert(boolean, true) -> true;

convert(boolean, false) -> false;

convert(boolean, "true") -> true;

convert(boolean, "false") -> false;

convert(boolean, <<"true">>) -> true;

convert(boolean, <<"false">>) -> false;

convert(atom, Value) when is_atom(Value) -> Value;

convert(atom, Value) when is_list(Value) -> list_to_atom(Value);

convert(atom, Value) when is_binary(Value) -> binary_to_atom(Value, utf8);

convert(number, Value) when is_number(Value) -> Value;

convert(number, Value) when is_binary(Value) ->
  convert(number, binary_to_list(Value));

convert(number, Value) when is_list(Value) ->
    case erl_scan:string(Value) of
      {ok, [{integer, _, I}],_} -> I;
      {ok, [{float, _, F}],_} -> F
    end.


parse_config(Element = #xmlElement{name = dyn_variable}, Conf = #config{}) ->
    ts_config:parse(Element, Conf);

parse_config(Element = #xmlElement{name = mainframe},
             Config = #config{curid = Id, session_tab = Tab,
                              sessions = [CurS | _], dynvar = DynVar,
                              subst = SubstFlag, match = MatchRegExp}) ->
    Type = xml_attrib_value(atom, Element, type),
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


%==============================================================================
% Internal Functions
%==============================================================================

build_request(connect, Element) ->
    ClientId = xml_attrib(string, Element, client_id, uuid()),
    #mainframe_connect{client_id = ClientId};

build_request(login, Element) ->
    Username = xml_attrib(string, Element, username, ?DEFAULT_USERNAME),
    Password = xml_attrib(string, Element, password, ?DEFAULT_PASSWORD),
    Payload = #mainframe_login{username = Username, password = Password},
    #mainframe_request{id = uuid(), name = <<"login">>, payload = Payload};

build_request(graphql, Element) ->
    Vars = parse_variables(Element),
    {Type, Version, Name, Graphql} = parse_graphql(Element),
    ReqName = case Type of
      query -> <<"graphql.perform">>;
      mutation -> <<"graphql.perform">>;
      subscription -> <<"graphql.subscribe">>
    end,
    Payload = #mainframe_graphql{type = Type,
                                 name = Name,
                                 graphql = Graphql,
                                 variables = Vars,
                                 version = Version},
    #mainframe_request{id = uuid(), name = ReqName, payload = Payload};

build_request(close, _Element) ->
    #mainframe_close{}.


parse_variables(Element) ->
    case xml_child(Element, variables, null) of
      null -> [];
      #xmlElement{} = Child ->
        {ok, Vars} = parse_variable_object(Child),
        Vars
    end.


parse_graphql(Element) ->
    case xml_child(Element, query, null) of
      null ->
        case xml_child(Element, mutation, null) of
          null ->
            Child = xml_child(Element, subscription),
            Ver = case xml_attrib(string, Element, version, <<>>) of
              ?MV{value = <<>>} -> undefined;
              Value -> Value
            end,
            parse_graphql(Child, subscription, Ver, ?GRAPHQL_SUBSCRIPTION_NAME_RX);
          Child ->
            parse_graphql(Child, mutation, undefined, ?GRAPHQL_MUTATION_NAME_RX)
        end;
      Child ->
        parse_graphql(Child, query, undefined, ?GRAPHQL_QUERY_NAME_RX)
    end.


parse_graphql(Element, Type, Ver, Regex) ->
    Name = xml_attrib(string, Element, name, <<>>),
    Graphql = xml_text(string, Element),
    Post = fun(V) -> re:replace(V, "\n +", "\n", [global, {return, binary}]) end,
    parse_graphql_name(Name, post_value(Graphql, Post), Type, Ver, Regex).


parse_graphql_name(?MV{value = <<>>}, ?MV{value = Data} = Graphql, Type, Ver, Regex) ->
    ReOpts = [{capture, all_but_first, binary}],
    case re:run(Data, Regex, ReOpts) of
      {match, [Name]} -> {Type, Ver, mainframe_value(string, Name), Graphql};
      _ -> {Type, Ver, mainframe_value(string, "Undefined"), Graphql}
    end;

parse_graphql_name(?MV{} = Name, Graphql, Type, Ver, _Regex) ->
    {Type, Ver, Name, Graphql}.


parse_variable_value(#xmlText{}) -> ignore;

parse_variable_value(#xmlComment{}) -> ignore;

parse_variable_value(Element = #xmlElement{name = number}) ->
    {ok, xml_text(number, Element)};

parse_variable_value(Element = #xmlElement{name = boolean}) ->
    {ok, xml_text(boolean, Element)};

parse_variable_value(Element = #xmlElement{name = string}) ->
    Value = xml_text(string, Element),
    case ?VALUE(xml_attrib(boolean, Element, empty_as_null, false)) of
      false -> {ok, Value};
      true ->
        Post = fun(<<>>) -> null; (V) -> V end,
        {ok, post_value(Value, Post)}
    end;

parse_variable_value(Element = #xmlElement{name = list}) ->
    parse_variable_list(Element);

parse_variable_value(Element = #xmlElement{name = object}) ->
    parse_variable_object(Element);

parse_variable_value(Element = #xmlElement{name = message}) ->
    parse_variable_message(Element);

parse_variable_value(#xmlElement{name = null}) ->
    {ok, ?MV{}}.


parse_variable_object(#xmlElement{content = Content}) ->
    Values = [{N, V} || {ok, N, V} <- [parse_variable_item(E) || E <- Content]],
    {ok, ?MV{type = object, ready = maybe, value = Values}}.


parse_variable_list(#xmlElement{content = Content}) ->
    Values = [V || {ok, V} <- [parse_variable_value(E) || E <- Content]],
    {ok, ?MV{type = list, ready = maybe, value = Values}}.


parse_variable_item(Element) ->
  case parse_variable_value(Element) of
    {ok, V} -> {ok, xml_attrib(string, Element, name), V};
    Other -> Other
  end.


parse_variable_message(Element) ->
  ?DebugF("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC~n~p~n", [Element]),
  BodyElem = xml_child(Element, body),
  Body = xml_text(string, BodyElem),
  Id = uuid(),
  {ok, ?MV_OBJ([
    {<<"blocks">>, ?MV_OBJ([
      {<<"objectBlocks">>, ?MV_LIST([])},
      {<<"previewBlocks">>, ?MV_LIST([])},
      {<<"blockKeyOrder">>, ?MV_LIST([?MV_STR(Id)])},
      {<<"textBlocks">>, ?MV_LIST([
        ?MV_OBJ([
          {<<"type">>, ?MV_STR(<<"TEXT">>)},
          {<<"key">>, ?MV_STR(Id)},
          {<<"body">>, Body},
          {<<"attributes">>, ?MV_OBJ([
            {<<"highlights">>, ?MV_LIST([])},
            {<<"styles">>, ?MV_LIST([])}
          ])}
        ])
      ])}
    ])},
    {<<"references">>, ?MV_OBJ([
      {<<"actions">>, ?MV_LIST([])},
      {<<"attachments">>, ?MV_LIST([])},
      {<<"blocks">>, ?MV_LIST([])},
      {<<"mentions">>, ?MV_LIST([])}
    ])}
  ])}.


xml_attrib_value(Type, Element, Name) ->
  ?MV{ready = true, value = Value} = xml_attrib(Type, Element, Name),
  Value.


xml_attrib(Type, #xmlElement{attributes = Attribs}, Name) ->
  xml_attrib(Type, Attribs, Name);

xml_attrib(Type, [#xmlAttribute{name = Name, value = Value} | _], Name) ->
  mainframe_value(Type, Value);

xml_attrib(Type, [_ | Rest], Name) ->
  xml_attrib(Type, Rest, Name);

xml_attrib(_Type, [], Name) ->
  throw({missing_attribute, Name}).


xml_attrib(Type, #xmlElement{attributes = Attribs}, Name, Default) ->
  xml_attrib(Type, Attribs, Name, Default);

xml_attrib(Type, [#xmlAttribute{name = Name, value = Value} | _], Name, _Default) ->
  mainframe_value(Type, Value);

xml_attrib(Type, [_ | Rest], Name, Default) ->
  xml_attrib(Type, Rest, Name, Default);

xml_attrib(Type, [], _Name, Default) ->
  mainframe_value(Type, Default).


xml_text(Type, #xmlElement{content = Content}) ->
  xml_text(Type, Content);

xml_text(Type, [#xmlText{value = Value} | _]) ->
  mainframe_value(Type, string:trim(Value, both, "\n\t ")).


xml_child(#xmlElement{content = Content}, Name) -> xml_child(Content, Name);

xml_child([Element = #xmlElement{name = Name} | _], Name) -> Element;

xml_child([_ | Rest], Name) -> xml_child(Rest, Name);

xml_child([], Name) -> throw({missing_element, Name}).


xml_child(#xmlElement{content = Content}, Name, Default) ->
  xml_child(Content, Name, Default);

xml_child([Element = #xmlElement{name = Name} | _], Name, _Default) -> Element;

xml_child([_ | Rest], Name, Default) -> xml_child(Rest, Name, Default);

xml_child([], _Name, Default) -> Default.


mainframe_value(number, [$%, $% | _] = Value) ->
    mainframe_value(number, list_to_binary(Value));

mainframe_value(boolean, [$%, $% | _] = Value) ->
    mainframe_value(boolean, list_to_binary(Value));

mainframe_value(atom, [$%, $% | _] = Value) ->
    mainframe_value(atom, list_to_binary(Value));

mainframe_value(number, <<$%, $%, _/binary>> = Value) ->
    case is_var(Value) of
      true -> ?MV{type = number, ready = false, value = Value};
      false -> throw({bad_number, Value})
    end;

mainframe_value(boolean, <<$%, $%, _/binary>> = Value) ->
    case is_var(Value) of
      true -> ?MV{type = boolean, ready = false, value = Value};
      false -> throw({bad_boolean, Value})
    end;

mainframe_value(atom, <<$%, $%, _/binary>> = Value) ->
    case is_var(Value) of
      true -> ?MV{type = atom, ready = false, value = Value};
      false -> throw({bad_atom, Value})
    end;

mainframe_value(string, Value) ->
    case has_var(Value) of
      true -> ?MV{type = string, ready = false, value = convert(string, Value)};
      false -> ?MV{type = string, ready = true, value = convert(string, Value)}
    end;

mainframe_value(null, Value)
  when Value =:= null; Value =:= nil ->
    ?MV{type = null, ready = true, value = Value};

mainframe_value(list, Values) when is_list(Values) ->
    {ReversedValues, Ready} = lists:foldl(
      fun(?MV{ready = R1} = V, {Acc, R2}) -> {[V | Acc], R1 and R2} end,
      {[], true}, Values),
    ?MV{type = list, ready = Ready, value = lists:reverse(ReversedValues)};

mainframe_value(object, Values) when is_list(Values) ->
    {ReversedItems, Ready} = lists:foldl(fun
      ({?MV{ready = R1} = N, ?MV{ready = R2} = V}, {Acc, R3}) ->
        {[{N, V} | Acc], R1 and R2 and R3};
      ({N, ?MV{ready = R1} = V}, {Acc, R2}) ->
        {[{mainframe_value(string, N), V} | Acc], R1 and R2}
      end,
      {[], true}, Values),
    ?MV{type = object, ready = Ready, value = lists:reverse(ReversedItems)};

mainframe_value(Type, Value) ->
    ?MV{type = Type, ready = true, value = convert(Type, Value)}.


post_value(?MV{post = undefined, ready = true, value = Value} = Spec, Post)
  when is_function(Post) -> Spec?MV{value = Post(Value)};

post_value(?MV{post = undefined} = Spec, Post)
  when is_function(Post) -> Spec?MV{post = Post}.


post_subst(?MV{post = undefined} = Spec, Value) ->
  Spec?MV{ready = true, value = Value};

post_subst(?MV{post = Fun} = Spec, Value) ->
  Spec?MV{ready = true, value = Fun(Value)}.


is_var(Value) when is_list(Value); is_binary(Value) ->
  % Not completly exact but a good enough aproximation...
  case re:run(Value, "^%%_?[a-zA-Z][a-zA-Z0-9_:]*%%$") of
    {match, _} -> true;
    _ -> false
  end.


has_var(Value) when is_list(Value); is_binary(Value) ->
  % Not completly exact but a good enough aproximation...
  case re:run(Value, "%%_?[a-zA-Z][a-zA-Z0-9_:]*%%") of
    {match, _} -> true;
    _ -> false
  end.

