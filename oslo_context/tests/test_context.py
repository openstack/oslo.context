# -*- encoding: utf-8 -*-
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

import uuid

from oslotest import base as test_base

from oslo_context import context
from oslo_context import fixture


class Object(object):
    pass


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
        self.assertFalse(ctx1.is_admin)

    def test_store_current(self):
        # By default a new context is stored.
        ctx = context.RequestContext()
        self.assertIs(context.get_current(), ctx)

    def test_no_context(self):
        self.assertIsNone(context.get_current())

    def test_admin_context_show_deleted_flag_default(self):
        ctx = context.get_admin_context()
        self.assertIsInstance(ctx, context.RequestContext)
        self.assertTrue(ctx.is_admin)
        self.assertFalse(ctx.show_deleted)
        self.assertIsNone(ctx.tenant)

    def test_admin_context_show_deleted_flag_set(self):
        ctx = context.get_admin_context(show_deleted=True)
        self.assertTrue(ctx.is_admin)
        self.assertTrue(ctx.show_deleted)

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

    def test_from_dict_unknown_keys(self):
        dct = {
            "auth_token": "token1",
            "user": "user1",
            "read_only": True,
            "roles": "role1,role2,role3",  # future review provides this
            "color": "red",
            "unknown": ""
        }
        ctx = context.RequestContext.from_dict(dct)
        self.assertEqual("token1", ctx.auth_token)
        self.assertEqual("user1", ctx.user)
        self.assertIsNone(ctx.tenant)
        self.assertFalse(ctx.is_admin)
        self.assertTrue(ctx.read_only)
        self.assertRaises(KeyError, lambda: ctx.__dict__['color'])

    def test_is_user_context(self):
        self.assertFalse(context.is_user_context(None))
        ctx = context.RequestContext(is_admin=True)
        self.assertFalse(context.is_user_context(ctx))
        ctx = context.RequestContext(is_admin=False)
        self.assertTrue(context.is_user_context(ctx))
        self.assertFalse(context.is_user_context("non context object"))

    def test_from_environ_variables(self):
        auth_token = uuid.uuid4().hex
        user_id = uuid.uuid4().hex
        project_id = uuid.uuid4().hex
        user_domain_id = uuid.uuid4().hex
        project_domain_id = uuid.uuid4().hex
        roles = [uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex]

        environ = {'HTTP_X_AUTH_TOKEN': auth_token,
                   'HTTP_X_USER_ID': user_id,
                   'HTTP_X_PROJECT_ID': project_id,
                   'HTTP_X_USER_DOMAIN_ID': user_domain_id,
                   'HTTP_X_PROJECT_DOMAIN_ID': project_domain_id,
                   'HTTP_X_ROLES': ','.join(roles)}

        ctx = context.RequestContext.from_environ(environ)

        self.assertEqual(auth_token, ctx.auth_token)
        self.assertEqual(user_id, ctx.user)
        self.assertEqual(project_id, ctx.tenant)
        self.assertEqual(user_domain_id, ctx.user_domain)
        self.assertEqual(project_domain_id, ctx.project_domain)
        self.assertEqual(roles, ctx.roles)

    def test_from_environ_no_roles(self):
        ctx = context.RequestContext.from_environ(environ={})
        self.assertEqual([], ctx.roles)

        ctx = context.RequestContext.from_environ(environ={'HTTP_X_ROLES': ''})
        self.assertEqual([], ctx.roles)

    def test_from_environ_deprecated_variables(self):
        value = uuid.uuid4().hex

        environ = {'HTTP_X_USER': value}
        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual(value, ctx.user)

        environ = {'HTTP_X_TENANT_ID': value}
        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual(value, ctx.tenant)

        environ = {'HTTP_X_STORAGE_TOKEN': value}
        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual(value, ctx.auth_token)

        environ = {'HTTP_X_TENANT': value}
        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual(value, ctx.tenant)

        environ = {'HTTP_X_ROLE': value}
        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual([value], ctx.roles)

    def test_from_environ_deprecated_precendence(self):
        old = uuid.uuid4().hex
        new = uuid.uuid4().hex
        override = uuid.uuid4().hex

        environ = {'HTTP_X_USER': old,
                   'HTTP_X_USER_ID': new}

        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual(ctx.user, new)

        ctx = context.RequestContext.from_environ(environ=environ,
                                                  user=override)
        self.assertEqual(ctx.user, override)

        environ = {'HTTP_X_TENANT': old,
                   'HTTP_X_PROJECT_ID': new}

        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual(ctx.tenant, new)

        ctx = context.RequestContext.from_environ(environ=environ,
                                                  tenant=override)
        self.assertEqual(ctx.tenant, override)

    def test_from_environ_strip_roles(self):
        environ = {'HTTP_X_ROLES': ' abc\t,\ndef\n,ghi\n\n'}
        ctx = context.RequestContext.from_environ(environ=environ)
        self.assertEqual(['abc', 'def', 'ghi'], ctx.roles)

    def test_from_function_and_args(self):
        ctx = context.RequestContext(user="user1")
        arg = []
        kw = dict(c=ctx, s="s")
        fn = context.get_context_from_function_and_args
        ctx1 = context.get_context_from_function_and_args(fn, arg, kw)
        self.assertIs(ctx1, ctx)

    def test_not_in_from_function_and_args(self):
        arg = []
        kw = dict()
        fn = context.get_context_from_function_and_args
        ctx1 = context.get_context_from_function_and_args(fn, arg, kw)
        self.assertIsNone(ctx1)

    def test_values(self):
        auth_token = "token1"
        # test unicode support
        user = u"John Gāo"
        tenant = "tenant1"
        domain = "domain1"
        user_domain = "user_domain1"
        project_domain = "project_domain1"
        is_admin = True
        read_only = True
        show_deleted = True
        request_id = "id1"
        resource_uuid = "uuid1"

        ctx = context.RequestContext(auth_token=auth_token,
                                     user=user,
                                     tenant=tenant,
                                     domain=domain,
                                     user_domain=user_domain,
                                     project_domain=project_domain,
                                     is_admin=is_admin,
                                     read_only=read_only,
                                     show_deleted=show_deleted,
                                     request_id=request_id,
                                     resource_uuid=resource_uuid)
        self.assertEqual(auth_token, ctx.auth_token)
        self.assertEqual(user, ctx.user)
        self.assertEqual(tenant, ctx.tenant)
        self.assertEqual(domain, ctx.domain)
        self.assertEqual(user_domain, ctx.user_domain)
        self.assertEqual(project_domain, ctx.project_domain)
        self.assertEqual(is_admin, ctx.is_admin)
        self.assertEqual(read_only, ctx.read_only)
        self.assertEqual(show_deleted, ctx.show_deleted)
        self.assertEqual(request_id, ctx.request_id)
        self.assertEqual(resource_uuid, ctx.resource_uuid)

        d = ctx.to_dict()
        self.assertIn('auth_token', d)
        self.assertIn('user', d)
        self.assertIn('tenant', d)
        self.assertIn('domain', d)
        self.assertIn('user_domain', d)
        self.assertIn('project_domain', d)
        self.assertIn('is_admin', d)
        self.assertIn('read_only', d)
        self.assertIn('show_deleted', d)
        self.assertIn('request_id', d)
        self.assertIn('resource_uuid', d)
        self.assertIn('user_identity', d)
        self.assertIn('roles', d)

        self.assertEqual(auth_token, d['auth_token'])
        self.assertEqual(tenant, d['tenant'])
        self.assertEqual(domain, d['domain'])
        self.assertEqual(user_domain, d['user_domain'])
        self.assertEqual(project_domain, d['project_domain'])
        self.assertEqual(is_admin, d['is_admin'])
        self.assertEqual(read_only, d['read_only'])
        self.assertEqual(show_deleted, d['show_deleted'])
        self.assertEqual(request_id, d['request_id'])
        self.assertEqual(resource_uuid, d['resource_uuid'])
        user_identity = "%s %s %s %s %s" % (user, tenant, domain,
                                            user_domain, project_domain)
        self.assertEqual(user_identity, d['user_identity'])
        self.assertEqual([], d['roles'])

    def test_get_logging_values(self):
        auth_token = "token1"
        user = "user1"
        tenant = "tenant1"
        domain = "domain1"
        user_domain = "user_domain1"
        project_domain = "project_domain1"
        is_admin = True
        read_only = True
        show_deleted = True
        request_id = "id1"
        resource_uuid = "uuid1"

        ctx = context.RequestContext(auth_token=auth_token,
                                     user=user,
                                     tenant=tenant,
                                     domain=domain,
                                     user_domain=user_domain,
                                     project_domain=project_domain,
                                     is_admin=is_admin,
                                     read_only=read_only,
                                     show_deleted=show_deleted,
                                     request_id=request_id,
                                     resource_uuid=resource_uuid)
        self.assertEqual(auth_token, ctx.auth_token)
        self.assertEqual(user, ctx.user)
        self.assertEqual(tenant, ctx.tenant)
        self.assertEqual(domain, ctx.domain)
        self.assertEqual(user_domain, ctx.user_domain)
        self.assertEqual(project_domain, ctx.project_domain)
        self.assertEqual(is_admin, ctx.is_admin)
        self.assertEqual(read_only, ctx.read_only)
        self.assertEqual(show_deleted, ctx.show_deleted)
        self.assertEqual(request_id, ctx.request_id)
        self.assertEqual(resource_uuid, ctx.resource_uuid)

        d = ctx.get_logging_values()
        self.assertIn('auth_token', d)
        self.assertIn('user', d)
        self.assertIn('tenant', d)
        self.assertIn('domain', d)
        self.assertIn('user_domain', d)
        self.assertIn('project_domain', d)
        self.assertIn('is_admin', d)
        self.assertIn('read_only', d)
        self.assertIn('show_deleted', d)
        self.assertIn('request_id', d)
        self.assertIn('resource_uuid', d)
        self.assertIn('user_identity', d)

        self.assertEqual(auth_token, d['auth_token'])
        self.assertEqual(tenant, d['tenant'])
        self.assertEqual(domain, d['domain'])
        self.assertEqual(user_domain, d['user_domain'])
        self.assertEqual(project_domain, d['project_domain'])
        self.assertEqual(is_admin, d['is_admin'])
        self.assertEqual(read_only, d['read_only'])
        self.assertEqual(show_deleted, d['show_deleted'])
        self.assertEqual(request_id, d['request_id'])
        self.assertEqual(resource_uuid, d['resource_uuid'])
        user_identity = "%s %s %s %s %s" % (user, tenant, domain,
                                            user_domain, project_domain)
        self.assertEqual(user_identity, d['user_identity'])

    def test_dict_empty_user_identity(self):
        ctx = context.RequestContext()
        d = ctx.to_dict()
        self.assertEqual("- - - - -", d['user_identity'])

    def test_generate_request_id(self):
        id = context.generate_request_id()
        self.assertEqual("req-", id[:4])

    def test_generate_request_id_unique(self):
        id1 = context.generate_request_id()
        id2 = context.generate_request_id()
        self.assertNotEqual(id1, id2)

    def test_policy_dict(self):
        user = uuid.uuid4().hex
        user_domain = uuid.uuid4().hex
        tenant = uuid.uuid4().hex
        project_domain = uuid.uuid4().hex
        roles = [uuid.uuid4().hex, uuid.uuid4().hex, uuid.uuid4().hex]

        ctx = context.RequestContext(user=user,
                                     user_domain=user_domain,
                                     tenant=tenant,
                                     project_domain=project_domain,
                                     roles=roles)

        self.assertEqual({'user_id': user,
                          'user_domain_id': user_domain,
                          'project_id': tenant,
                          'project_domain_id': project_domain,
                          'roles': roles}, ctx.to_policy_values())
