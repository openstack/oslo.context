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

"""
Base class for holding contextual information of a request

This class has several uses:

* Used for storing security information in a web request.
* Used for passing contextual details to oslo.log.

Projects should subclass this class if they wish to enhance the request
context or provide additional information in their specific WSGI pipeline
or logging context.
"""

import collections.abc
import functools
import itertools
import threading
import typing as ty
import uuid
import warnings

import debtcollector
from debtcollector import renames


_request_store = threading.local()

# These arguments will be passed to a new context from the first available
# header to support backwards compatibility.
_ENVIRON_HEADERS: ty.Dict[str, ty.List[str]] = {
    'auth_token': ['HTTP_X_AUTH_TOKEN', 'HTTP_X_STORAGE_TOKEN'],
    'user_id': ['HTTP_X_USER_ID', 'HTTP_X_USER'],
    'project_id': ['HTTP_X_PROJECT_ID', 'HTTP_X_TENANT_ID', 'HTTP_X_TENANT'],
    'domain_id': ['HTTP_X_DOMAIN_ID'],
    'system_scope': ['HTTP_OPENSTACK_SYSTEM_SCOPE'],
    'user_domain_id': ['HTTP_X_USER_DOMAIN_ID'],
    'project_domain_id': ['HTTP_X_PROJECT_DOMAIN_ID'],
    'user_name': ['HTTP_X_USER_NAME'],
    'project_name': ['HTTP_X_PROJECT_NAME', 'HTTP_X_TENANT_NAME'],
    'user_domain_name': ['HTTP_X_USER_DOMAIN_NAME'],
    'project_domain_name': ['HTTP_X_PROJECT_DOMAIN_NAME'],
    'request_id': ['openstack.request_id'],
    'global_request_id': ['openstack.global_request_id'],

    'service_token': ['HTTP_X_SERVICE_TOKEN'],
    'service_user_id': ['HTTP_X_SERVICE_USER_ID'],
    'service_user_name': ['HTTP_X_SERVICE_USER_NAME'],
    'service_user_domain_id': ['HTTP_X_SERVICE_USER_DOMAIN_ID'],
    'service_user_domain_name': ['HTTP_X_SERVICE_USER_DOMAIN_NAME'],
    'service_project_id': ['HTTP_X_SERVICE_PROJECT_ID'],
    'service_project_name': ['HTTP_X_SERVICE_PROJECT_NAME'],
    'service_project_domain_id': ['HTTP_X_SERVICE_PROJECT_DOMAIN_ID'],
    'service_project_domain_name': ['HTTP_X_SERVICE_PROJECT_DOMAIN_NAME'],
}


def generate_request_id() -> str:
    """Generate a unique request id."""
    return 'req-%s' % uuid.uuid4()


class _DeprecatedPolicyValues(collections.abc.MutableMapping):
    """A Dictionary that manages current and deprecated policy values.

    Anything added to this dictionary after initial creation is considered a
    deprecated key that we are trying to move services away from. Accessing
    these values as oslo.policy will do will trigger a DeprecationWarning.
    """

    def __init__(self, data: ty.Dict[str, ty.Any]):
        self._data = data
        self._deprecated: ty.Dict[str, ty.Any] = {}

    def __getitem__(self, k: str) -> ty.Any:
        try:
            return self._data[k]
        except KeyError:
            pass

        try:
            val = self._deprecated[k]
        except KeyError:
            pass
        else:
            warnings.warn('Policy enforcement is depending on the value of '
                          '%s. This key is deprecated. Please update your '
                          'policy file to use the standard policy values.' % k,
                          DeprecationWarning)
            return val

        raise KeyError(k)

    def __setitem__(self, k: str, v: ty.Any) -> None:
        self._deprecated[k] = v

    def __delitem__(self, k: str) -> None:
        del self._deprecated[k]

    def __iter__(self) -> ty.Iterator[ty.Any]:
        return iter(self._dict)

    def __len__(self) -> int:
        return len(self._dict)

    def __str__(self) -> str:
        return self._dict.__str__()

    def __repr__(self) -> str:
        return self._dict.__repr__()

    @property
    def _dict(self) -> ty.Dict[str, ty.Any]:
        d = self._deprecated.copy()
        d.update(self._data)
        return d


# TODO(stephenfin): Remove this in the 4.0 release
def _moved_msg(new_name: str, old_name: ty.Optional[str]) -> None:
    if old_name:
        deprecated_msg = "Property '%(old_name)s' has moved to '%(new_name)s'"
        deprecated_msg = deprecated_msg % {'old_name': old_name,
                                           'new_name': new_name}

        debtcollector.deprecate(deprecated_msg,
                                version='2.6',
                                removal_version='3.0',
                                stacklevel=5)


def _moved_property(
    new_name: str,
    old_name: ty.Optional[str] = None,
    target: ty.Optional[str] = None,
) -> ty.Any:

    def getter(self: ty.Any) -> ty.Any:
        _moved_msg(new_name, old_name)
        return getattr(self, target or new_name)

    def setter(self: ty.Any, value: str) -> None:
        _moved_msg(new_name, old_name)
        setattr(self, target or new_name, value)

    def deleter(self: ty.Any) -> None:
        _moved_msg(new_name, old_name)
        delattr(self, target or new_name)

    return property(getter, setter, deleter)


_renamed_kwarg = functools.partial(renames.renamed_kwarg,
                                   version='2.18',
                                   removal_version='3.0',
                                   replace=True)


class RequestContext:

    """Helper class to represent useful information about a request context.

    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    user_idt_format = '{user} {project_id} {domain} {user_domain} {p_domain}'
    # Can be overridden in subclasses to specify extra keys that should be
    # read when constructing a context using from_dict.
    FROM_DICT_EXTRA_KEYS: ty.List[str] = []

    @_renamed_kwarg('user', 'user_id')
    @_renamed_kwarg('domain', 'domain_id')
    @_renamed_kwarg('user_domain', 'user_domain_id')
    @_renamed_kwarg('project_domain', 'project_domain_id')
    def __init__(
        self,
        auth_token: ty.Optional[str] = None,
        user_id: ty.Optional[str] = None,
        project_id: ty.Optional[str] = None,
        domain_id: ty.Optional[str] = None,
        user_domain_id: ty.Optional[str] = None,
        project_domain_id: ty.Optional[str] = None,
        is_admin: bool = False,
        read_only: bool = False,
        show_deleted: bool = False,
        request_id: ty.Optional[str] = None,
        resource_uuid: ty.Optional[str] = None,
        overwrite: bool = True,
        roles: ty.Optional[ty.List[str]] = None,
        user_name: ty.Optional[str] = None,
        project_name: ty.Optional[str] = None,
        domain_name: ty.Optional[str] = None,
        user_domain_name: ty.Optional[str] = None,
        project_domain_name: ty.Optional[str] = None,
        is_admin_project: bool = True,
        service_token: ty.Optional[str] = None,
        service_user_id: ty.Optional[str] = None,
        service_user_name: ty.Optional[str] = None,
        service_user_domain_id: ty.Optional[str] = None,
        service_user_domain_name: ty.Optional[str] = None,
        service_project_id: ty.Optional[str] = None,
        service_project_name: ty.Optional[str] = None,
        service_project_domain_id: ty.Optional[str] = None,
        service_project_domain_name: ty.Optional[str] = None,
        service_roles: ty.Optional[ty.List[str]] = None,
        global_request_id: ty.Optional[str] = None,
        system_scope: ty.Optional[str] = None,
    ):
        """Initialize the RequestContext

        :param overwrite: Set to False to ensure that the greenthread local
                          copy of the index is not overwritten.
        :param is_admin_project: Whether the specified project is specified in
                                 the token as the admin project. Defaults to
                                 True for backwards compatibility.
        :type is_admin_project: bool
        :param system_scope: The system scope of a token. The value ``all``
                             represents the entire deployment system. A service
                             ID represents a specific service within the
                             deployment system.
        :type system_scope: string
        """
        # setting to private variables to avoid triggering subclass properties
        self._user_id = user_id
        self._project_id = project_id
        self._domain_id = domain_id
        self._user_domain_id = user_domain_id
        self._project_domain_id = project_domain_id

        self.auth_token = auth_token
        self.user_name = user_name
        self.project_name = project_name
        self.domain_name = domain_name
        self.system_scope = system_scope
        self.user_domain_name = user_domain_name
        self.project_domain_name = project_domain_name
        self.is_admin = is_admin
        self.is_admin_project = is_admin_project
        self.read_only = read_only
        self.show_deleted = show_deleted
        self.resource_uuid = resource_uuid
        self.roles = roles or []

        self.service_token = service_token
        self.service_user_id = service_user_id
        self.service_user_name = service_user_name
        self.service_user_domain_id = service_user_domain_id
        self.service_user_domain_name = service_user_domain_name
        self.service_project_id = service_project_id
        self.service_project_name = service_project_name
        self.service_project_domain_id = service_project_domain_id
        self.service_project_domain_name = service_project_domain_name
        self.service_roles = service_roles or []

        if not request_id:
            request_id = generate_request_id()
        self.request_id = request_id
        self.global_request_id = global_request_id
        if overwrite or not get_current():
            self.update_store()

    # NOTE(jamielennox): To prevent circular lookups on subclasses that might
    # point user to user_id we make user/user_id  etc point
    # to the same private variable rather than each other.
    user = _moved_property('user_id', 'user', target='_user_id')
    domain = _moved_property('domain_id', 'domain', target='_domain_id')
    user_domain = _moved_property(
        'user_domain_id', 'user_domain', target='_user_domain_id')
    project_domain = _moved_property(
        'project_domain_id', 'project_domain', target='_project_domain_id')

    user_id = _moved_property('_user_id')
    project_id = _moved_property('_project_id')
    domain_id = _moved_property('_domain_id')
    user_domain_id = _moved_property('_user_domain_id')
    project_domain_id = _moved_property('_project_domain_id')

    def update_store(self) -> None:
        """Store the context in the current thread."""
        _request_store.context = self

    def to_policy_values(self) -> _DeprecatedPolicyValues:
        """A dictionary of context attributes to enforce policy with.

        oslo.policy enforcement requires a dictionary of attributes
        representing the current logged in user on which it applies policy
        enforcement. This dictionary defines a standard list of attributes that
        should be available for enforcement across services.

        It is expected that services will often have to override this method
        with either deprecated values or additional attributes used by that
        service specific policy.
        """
        # NOTE(jamielennox): We need a way to allow projects to provide old
        # deprecated policy values that trigger a warning when used in favour
        # of our standard ones. This object acts like a dict but only values
        # from oslo.policy don't show a warning.
        return _DeprecatedPolicyValues({
            'user_id': self.user_id,
            'user_domain_id': self.user_domain_id,
            'system_scope': self.system_scope,
            'domain_id': self.domain_id,
            'project_id': self.project_id,
            'project_domain_id': self.project_domain_id,
            'roles': self.roles,
            'is_admin_project': self.is_admin_project,
            'service_user_id': self.service_user_id,
            'service_user_domain_id': self.service_user_domain_id,
            'service_project_id': self.service_project_id,
            'service_project_domain_id': self.service_project_domain_id,
            'service_roles': self.service_roles,
        })

    def to_dict(self) -> ty.Dict[str, ty.Any]:
        """Return a dictionary of context attributes."""
        user_idt = self.user_idt_format.format(
            user=self.user_id or '-',
            project_id=self.project_id or '-',
            domain=self.domain_id or '-',
            user_domain=self.user_domain_id or '-',
            p_domain=self.project_domain_id or '-',
        )

        return {'user': self.user_id,
                'project_id': self.project_id,
                'system_scope': self.system_scope,
                'project': self.project_id,
                'domain': self.domain_id,
                'user_domain': self.user_domain_id,
                'project_domain': self.project_domain_id,
                'is_admin': self.is_admin,
                'read_only': self.read_only,
                'show_deleted': self.show_deleted,
                'auth_token': self.auth_token,
                'request_id': self.request_id,
                'global_request_id': self.global_request_id,
                'resource_uuid': self.resource_uuid,
                'roles': self.roles,
                'user_identity': user_idt,
                'is_admin_project': self.is_admin_project}

    def get_logging_values(self) -> ty.Dict[str, ty.Any]:
        """Return a dictionary of logging specific context attributes."""
        values = {'user_name': self.user_name,
                  'project_name': self.project_name,
                  'domain_name': self.domain_name,
                  'user_domain_name': self.user_domain_name,
                  'project_domain_name': self.project_domain_name}
        values.update(self.to_dict())
        if self.auth_token:
            # NOTE(jaosorior): Gotta obfuscate the token since this dict is
            # meant for logging and we shouldn't leak it.
            values['auth_token'] = '***'  # nosec
        else:
            values['auth_token'] = None
        # NOTE(bnemec: auth_token_info isn't defined in oslo.context, but it's
        # a common pattern in project context subclasses so we handle it here.
        # It largely contains things that we don't want logged, like the token
        # itself (which needs to be removed for security) and the catalog
        # (which needs to be removed because it bloats the logs terribly).
        values.pop('auth_token_info', None)

        return values

    @property
    def global_id(self) -> str:
        """Return a sensible value for global_id to pass on.

        When we want to make a call with to another service, it's
        important that we try to use global_request_id if available,
        and fall back to the locally generated request_id if not.
        """
        return self.global_request_id or self.request_id

    def redacted_copy(self, **kwargs: ty.Any) -> 'RequestContext':
        """Return a copy of the context with sensitive fields redacted.

        This is useful for creating a context that can be safely logged.

        :returns: A copy of the context with sensitive fields redacted.
        """
        return self.__class__(
            user_id=self.user_id,
            project_id=self.project_id,
            domain_id=self.domain_id,
            user_domain_id=self.user_domain_id,
            project_domain_id=self.project_domain_id,
            request_id=self.request_id,
            roles=self.roles,
            user_name=self.user_name,
            project_name=self.project_name,
            domain_name=self.domain_name,
            user_domain_name=self.user_domain_name,
            project_domain_name=self.project_domain_name,
            service_user_id=self.service_user_id,
            service_user_domain_id=self.service_user_domain_id,
            service_user_domain_name=self.service_user_domain_name,
            service_project_id=self.service_project_id,
            service_project_name=self.service_project_name,
            service_project_domain_id=self.service_project_domain_id,
            service_project_domain_name=self.service_project_domain_name,
            service_roles=self.service_roles,
            global_request_id=self.global_request_id,
            system_scope=self.system_scope,
            is_admin=self.is_admin,
            **kwargs
        )

    @classmethod
    @_renamed_kwarg('user', 'user_id')
    @_renamed_kwarg('domain', 'domain_id')
    @_renamed_kwarg('user_domain', 'user_domain_id')
    @_renamed_kwarg('project_domain', 'project_domain_id')
    def from_dict(
        cls, values: ty.Dict[str, ty.Any], **kwargs: ty.Any,
    ) -> 'RequestContext':
        """Construct a context object from a provided dictionary."""
        kwargs.setdefault('auth_token', values.get('auth_token'))
        kwargs.setdefault('user_id', values.get('user'))
        kwargs.setdefault('project_id', values.get('project_id'))
        kwargs.setdefault('domain_id', values.get('domain'))
        kwargs.setdefault('user_domain_id', values.get('user_domain'))
        kwargs.setdefault('project_domain_id', values.get('project_domain'))
        kwargs.setdefault('is_admin', values.get('is_admin', False))
        kwargs.setdefault('read_only', values.get('read_only', False))
        kwargs.setdefault('show_deleted', values.get('show_deleted', False))
        kwargs.setdefault('request_id', values.get('request_id'))
        kwargs.setdefault('global_request_id', values.get('global_request_id'))
        kwargs.setdefault('resource_uuid', values.get('resource_uuid'))
        kwargs.setdefault('roles', values.get('roles'))
        kwargs.setdefault('user_name', values.get('user_name'))
        kwargs.setdefault('project_name', values.get('project_name'))
        kwargs.setdefault('domain_name', values.get('domain_name'))
        kwargs.setdefault('user_domain_name', values.get('user_domain_name'))
        kwargs.setdefault('project_domain_name',
                          values.get('project_domain_name'))
        kwargs.setdefault('is_admin_project',
                          values.get('is_admin_project', True))
        kwargs.setdefault('system_scope', values.get('system_scope'))
        for key in cls.FROM_DICT_EXTRA_KEYS:
            kwargs.setdefault(key, values.get(key))
        return cls(**kwargs)

    @classmethod
    @_renamed_kwarg('user', 'user_id')
    @_renamed_kwarg('domain', 'domain_id')
    @_renamed_kwarg('user_domain', 'user_domain_id')
    @_renamed_kwarg('project_domain', 'project_domain_id')
    def from_environ(
        cls, environ: ty.Dict[str, ty.Any], **kwargs: ty.Any,
    ) -> 'RequestContext':
        """Load a context object from a request environment.

        If keyword arguments are provided then they override the values in the
        request environment.

        :param environ: The environment dictionary associated with a request.
        :type environ: dict
        """
        # Load a new context object from the environment variables set by
        # auth_token middleware. See:
        # https://docs.openstack.org/keystonemiddleware/latest/api/keystonemiddleware.auth_token.html#what-auth-token-adds-to-the-request-for-use-by-the-openstack-service

        # add kwarg if not specified by user from a list of possible headers
        for k, v_list in _ENVIRON_HEADERS.items():
            if k in kwargs:
                continue

            for v in v_list:
                if v in environ:
                    kwargs[k] = environ[v]
                    break

        if 'roles' not in kwargs:
            roles = environ.get('HTTP_X_ROLES', environ.get('HTTP_X_ROLE'))
            roles = [r.strip() for r in roles.split(',')] if roles else []
            kwargs['roles'] = roles

        if 'service_roles' not in kwargs:
            roles = environ.get('HTTP_X_SERVICE_ROLES')
            roles = [r.strip() for r in roles.split(',')] if roles else []
            kwargs['service_roles'] = roles

        if 'is_admin_project' not in kwargs:
            # NOTE(jamielennox): we default is_admin_project to true because if
            # nothing is provided we have to assume it is the admin project to
            # make old policy continue to work.
            is_admin_proj_str = environ.get('HTTP_X_IS_ADMIN_PROJECT', 'true')
            kwargs['is_admin_project'] = is_admin_proj_str.lower() == 'true'

        return cls(**kwargs)


def get_admin_context(show_deleted: bool = False) -> RequestContext:
    """Create an administrator context."""
    context = RequestContext(None,
                             project_id=None,
                             is_admin=True,
                             show_deleted=show_deleted,
                             overwrite=False)
    return context


def get_context_from_function_and_args(
    function: ty.Callable,
    args: ty.List[ty.Any],
    kwargs: ty.Dict[str, ty.Any],
) -> ty.Optional[RequestContext]:
    """Find an arg of type RequestContext and return it.

    This is useful in a couple of decorators where we don't know much about the
    function we're wrapping.
    """
    for arg in itertools.chain(kwargs.values(), args):
        if isinstance(arg, RequestContext):
            return arg

    return None


def is_user_context(context: RequestContext) -> bool:
    """Indicates if the request context is a normal user."""
    if not context or not isinstance(context, RequestContext):
        return False
    if context.is_admin:
        return False
    return True


def get_current() -> ty.Optional[RequestContext]:
    """Return this thread's current context

    If no context is set, returns None
    """
    return getattr(_request_store, 'context', None)
