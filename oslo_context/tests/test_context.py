# Copyright 2011 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslotest import base as test_base

from oslo_context import context
from oslo_context import fixture


class ContextTest(test_base.BaseTestCase):

    def setUp(self):
        super(ContextTest, self).setUp()
        self.useFixture(fixture.ClearRequestContext())

    def test_context(self):
        ctx = context.RequestContext()
        self.assertTrue(ctx)

    def test_store_when_no_overwrite(self):
        # If no context exists we store one even if overwrite is false
        # (since we are not overwriting anything).
        ctx = context.RequestContext(overwrite=False)
        self.assertIs(context.get_current(), ctx)

    def test_no_overwrite(self):
        # If there is already a context in the cache a new one will
        # not overwrite it if overwrite=False.
        ctx1 = context.RequestContext(overwrite=True)
        context.RequestContext(overwrite=False)
        self.assertIs(context.get_current(), ctx1)

    def test_admin_no_overwrite(self):
        # If there is already a context in the cache creating an admin
        # context will not overwrite it.
        ctx1 = context.RequestContext(overwrite=True)
        context.get_admin_context()
        self.assertIs(context.get_current(), ctx1)

    def test_store_current(self):
        # By default a new context is stored.
        ctx = context.RequestContext()
        self.assertIs(context.get_current(), ctx)

    def test_admin_context_show_deleted_flag_default(self):
        ctx = context.get_admin_context()
        self.assertFalse(ctx.show_deleted)

    def test_from_dict(self):
        dct = {
            "auth_token": "token1",
            "user": "user1",
            "tenant": "tenant1",
            "domain": "domain1",
            "user_domain": "user_domain1",
            "project_domain": "project_domain1",
            "is_admin": True,
            "read_only": True,
            "show_deleted": True,
            "request_id": "request1",
            "resource_uuid": "instance1",
            "extra_data": "foo"
        }
        ctx = context.RequestContext.from_dict(dct)
        self.assertEqual("token1", ctx.auth_token)
        self.assertEqual("user1", ctx.user)
        self.assertEqual("tenant1", ctx.tenant)
        self.assertEqual("domain1", ctx.domain)
        self.assertEqual("user_domain1", ctx.user_domain)
        self.assertEqual("project_domain1", ctx.project_domain)
        self.assertTrue(ctx.is_admin)
        self.assertTrue(ctx.read_only)
        self.assertTrue(ctx.show_deleted)
        self.assertEqual("request1", ctx.request_id)
        self.assertEqual("instance1", ctx.resource_uuid)
