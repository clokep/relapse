# Copyright 2014-2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import TYPE_CHECKING, Union

from relapse.api.errors import (
    NotFoundError,
    RelapseError,
    StoreError,
    UnrecognizedRequestError,
)
from relapse.handlers.push_rules import InvalidRuleException, RuleSpec, check_actions
from relapse.http.server import HttpServer
from relapse.http.servlet import (
    RestServlet,
    parse_json_value_from_request,
    parse_string,
)
from relapse.http.site import RelapseRequest
from relapse.push.rulekinds import PRIORITY_CLASS_MAP
from relapse.rest.client._base import client_patterns
from relapse.storage.push_rule import InconsistentRuleException, RuleNotFoundException
from relapse.types import JsonDict
from relapse.util.async_helpers import Linearizer

if TYPE_CHECKING:
    from relapse.server import HomeServer


class PushRuleRestServlet(RestServlet):
    PATTERNS = client_patterns("/(?P<path>pushrules/.*)$", v1=True)
    SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR = (
        "Unrecognised request: You probably wanted a trailing slash"
    )

    WORKERS_DENIED_METHODS = ["PUT", "DELETE"]
    CATEGORY = "Push rule requests"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.notifier = hs.get_notifier()
        self._is_worker = hs.config.worker.worker_app is not None
        self._push_rules_handler = hs.get_push_rules_handler()
        self._push_rule_linearizer = Linearizer(name="push_rules")

    async def on_PUT(self, request: RelapseRequest, path: str) -> tuple[int, JsonDict]:
        if self._is_worker:
            raise Exception("Cannot handle PUT /push_rules on worker")

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        async with self._push_rule_linearizer.queue(user_id):
            return await self.handle_put(request, path, user_id)

    async def handle_put(
        self, request: RelapseRequest, path: str, user_id: str
    ) -> tuple[int, JsonDict]:
        spec = _rule_spec_from_path(path.split("/"))
        try:
            priority_class = _priority_class_from_spec(spec)
        except InvalidRuleException as e:
            raise RelapseError(400, str(e))

        if "/" in spec.rule_id or "\\" in spec.rule_id:
            raise RelapseError(400, "rule_id may not contain slashes")

        content = parse_json_value_from_request(request)

        if spec.attr:
            try:
                await self._push_rules_handler.set_rule_attr(user_id, spec, content)
            except InvalidRuleException as e:
                raise RelapseError(400, "Invalid actions: %s" % e)
            except RuleNotFoundException:
                raise NotFoundError("Unknown rule")

            return 200, {}

        if spec.rule_id.startswith("."):
            # Rule ids starting with '.' are reserved for server default rules.
            raise RelapseError(400, "cannot add new rule_ids that start with '.'")

        try:
            (conditions, actions) = _rule_tuple_from_request_object(
                spec.template, spec.rule_id, content
            )
        except InvalidRuleException as e:
            raise RelapseError(400, str(e))

        before = parse_string(request, "before")
        if before:
            before = f"global/{spec.template}/{before}"

        after = parse_string(request, "after")
        if after:
            after = f"global/{spec.template}/{after}"

        try:
            await self.store.add_push_rule(
                user_id=user_id,
                rule_id=f"global/{spec.template}/{spec.rule_id}",
                priority_class=priority_class,
                conditions=conditions,
                actions=actions,
                before=before,
                after=after,
            )
            self._push_rules_handler.notify_user(user_id)
        except InconsistentRuleException as e:
            raise RelapseError(400, str(e))
        except RuleNotFoundException as e:
            raise RelapseError(400, str(e))

        return 200, {}

    async def on_DELETE(
        self, request: RelapseRequest, path: str
    ) -> tuple[int, JsonDict]:
        if self._is_worker:
            raise Exception("Cannot handle DELETE /push_rules on worker")

        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        async with self._push_rule_linearizer.queue(user_id):
            return await self.handle_delete(request, path, user_id)

    async def handle_delete(
        self,
        request: RelapseRequest,
        path: str,
        user_id: str,
    ) -> tuple[int, JsonDict]:
        spec = _rule_spec_from_path(path.split("/"))

        namespaced_rule_id = f"global/{spec.template}/{spec.rule_id}"

        try:
            await self.store.delete_push_rule(user_id, namespaced_rule_id)
            self._push_rules_handler.notify_user(user_id)
            return 200, {}
        except StoreError as e:
            if e.code == 404:
                raise NotFoundError()
            else:
                raise

    async def on_GET(self, request: RelapseRequest, path: str) -> tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester.user.to_string()

        # we build up the full structure and then decide which bits of it
        # to send which means doing unnecessary work sometimes but is
        # is probably not going to make a whole lot of difference
        rules = await self._push_rules_handler.push_rules_for_user(requester.user)

        path_parts = path.split("/")[1:]

        if path_parts == []:
            # we're a reference impl: pedantry is our job.
            raise UnrecognizedRequestError(
                PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
            )

        if path_parts[0] == "":
            return 200, rules
        elif path_parts[0] == "global":
            result = _filter_ruleset_with_path(rules["global"], path_parts[1:])
            return 200, result
        else:
            raise UnrecognizedRequestError()


def _rule_spec_from_path(path: list[str]) -> RuleSpec:
    """Turn a sequence of path components into a rule spec

    Args:
        path: the URL path components.

    Returns:
        rule spec, containing scope/template/rule_id entries, and possibly attr.

    Raises:
        UnrecognizedRequestError if the path components cannot be parsed.
    """
    if len(path) < 2:
        raise UnrecognizedRequestError()
    if path[0] != "pushrules":
        raise UnrecognizedRequestError()

    scope = path[1]
    path = path[2:]
    if scope != "global":
        raise UnrecognizedRequestError()

    if len(path) == 0:
        raise UnrecognizedRequestError()

    template = path[0]
    path = path[1:]

    if len(path) == 0 or len(path[0]) == 0:
        raise UnrecognizedRequestError()

    rule_id = path[0]

    path = path[1:]

    attr = None
    if len(path) > 0 and len(path[0]) > 0:
        attr = path[0]

    return RuleSpec(scope, template, rule_id, attr)


def _rule_tuple_from_request_object(
    rule_template: str, rule_id: str, req_obj: JsonDict
) -> tuple[list[JsonDict], list[Union[str, JsonDict]]]:
    if rule_template in ["override", "underride"]:
        if "conditions" not in req_obj:
            raise InvalidRuleException("Missing 'conditions'")
        conditions = req_obj["conditions"]
        for c in conditions:
            if "kind" not in c:
                raise InvalidRuleException("Condition without 'kind'")
    elif rule_template == "room":
        conditions = [{"kind": "event_match", "key": "room_id", "pattern": rule_id}]
    elif rule_template == "sender":
        conditions = [{"kind": "event_match", "key": "user_id", "pattern": rule_id}]
    elif rule_template == "content":
        if "pattern" not in req_obj:
            raise InvalidRuleException("Content rule missing 'pattern'")
        pat = req_obj["pattern"]

        conditions = [{"kind": "event_match", "key": "content.body", "pattern": pat}]
    else:
        raise InvalidRuleException("Unknown rule template: %s" % (rule_template,))

    if "actions" not in req_obj:
        raise InvalidRuleException("No actions found")
    actions = req_obj["actions"]

    check_actions(actions)

    return conditions, actions


def _filter_ruleset_with_path(ruleset: JsonDict, path: list[str]) -> JsonDict:
    if path == []:
        raise UnrecognizedRequestError(
            PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
        )

    if path[0] == "":
        return ruleset
    template_kind = path[0]
    if template_kind not in ruleset:
        raise UnrecognizedRequestError()
    path = path[1:]
    if path == []:
        raise UnrecognizedRequestError(
            PushRuleRestServlet.SLIGHTLY_PEDANTIC_TRAILING_SLASH_ERROR
        )
    if path[0] == "":
        return ruleset[template_kind]
    rule_id = path[0]

    the_rule = None
    for r in ruleset[template_kind]:
        if r["rule_id"] == rule_id:
            the_rule = r
    if the_rule is None:
        raise NotFoundError()

    path = path[1:]
    if len(path) == 0:
        return the_rule

    attr = path[0]
    if attr in the_rule:
        # Make sure we return a JSON object as the attribute may be a
        # JSON value.
        return {attr: the_rule[attr]}
    else:
        raise UnrecognizedRequestError()


def _priority_class_from_spec(spec: RuleSpec) -> int:
    if spec.template not in PRIORITY_CLASS_MAP.keys():
        raise InvalidRuleException("Unknown template: %s" % (spec.template))
    pc = PRIORITY_CLASS_MAP[spec.template]

    return pc


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    PushRuleRestServlet(hs).register(http_server)
