# Copyright 2016 OpenMarket Ltd
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

import logging

from twisted.web.resource import Resource

from relapse.http.server import UnrecognizedRequestResource

logger = logging.getLogger(__name__)


def create_resource_tree(
    desired_tree: dict[str, Resource], root_resource: Resource
) -> Resource:
    """Create the resource tree for this homeserver.

    This in unduly complicated because Twisted does not support putting
    child resources more than 1 level deep at a time.

    Args:
        desired_tree: Dict from desired paths to desired resources.
        root_resource: The root resource to add the tree to.
    Returns:
        The ``root_resource`` with a tree of child resources added to it.
    """

    # ideally we'd just use getChild and putChild but getChild doesn't work
    # unless you give it a Request object IN ADDITION to the name :/ So
    # instead, we'll store a copy of this mapping so we can actually add
    # extra resources to existing nodes. See self._resource_id for the key.
    resource_mappings: dict[str, Resource] = {}
    for full_path_str, res in desired_tree.items():
        # twisted requires all resources to be bytes
        full_path = full_path_str.encode("utf-8")

        logger.info("Attaching %s to path %s", res, full_path)
        last_resource = root_resource
        for path_seg in full_path.split(b"/")[1:-1]:
            if path_seg not in last_resource.listNames():
                # resource doesn't exist, so make a "dummy resource"
                child_resource: Resource = UnrecognizedRequestResource()
                last_resource.putChild(path_seg, child_resource)
                res_id = _resource_id(last_resource, path_seg)
                resource_mappings[res_id] = child_resource
                last_resource = child_resource
            else:
                # we have an existing Resource, use that instead.
                res_id = _resource_id(last_resource, path_seg)
                last_resource = resource_mappings[res_id]

        # ===========================
        # now attach the actual desired resource
        last_path_seg = full_path.split(b"/")[-1]

        # if there is already a resource here, thieve its children and
        # replace it
        res_id = _resource_id(last_resource, last_path_seg)
        if res_id in resource_mappings:
            # there is a dummy resource at this path already, which needs
            # to be replaced with the desired resource.
            existing_dummy_resource = resource_mappings[res_id]
            for child_name in existing_dummy_resource.listNames():
                child_res_id = _resource_id(existing_dummy_resource, child_name)
                child_resource = resource_mappings[child_res_id]
                # steal the children
                res.putChild(child_name, child_resource)

        # finally, insert the desired resource in the right place
        last_resource.putChild(last_path_seg, res)
        res_id = _resource_id(last_resource, last_path_seg)
        resource_mappings[res_id] = res

    return root_resource


def _resource_id(resource: Resource, path_seg: bytes) -> str:
    """Construct an arbitrary resource ID so you can retrieve the mapping
    later.

    If you want to represent resource A putChild resource B with path C,
    the mapping should looks like _resource_id(A,C) = B.

    Args:
        resource: The *parent* Resourceb
        path_seg: The name of the child Resource to be attached.
    Returns:
        A unique string which can be a key to the child Resource.
    """
    return "%s-%r" % (resource, path_seg)
