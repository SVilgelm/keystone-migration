#!/usr/bin/env python

import argparse
import collections
import ConfigParser as configparser
import copy
import datetime
import httplib
import json
import random
import string
import sys
import urlparse


def log(s):
    sys.stderr.write('%s: %s\n' % (datetime.datetime.now(), s))
    sys.stderr.flush()


class Config(object):
    def __init__(self, config):
        self.auth_url = config['auth_url']
        self.username = config['username']
        self.password = config['password']
        self.domain = config['domain']
        self.project = config['project']


class MigrationConfig(object):
    def __init__(self, parser):
        self.domains = self._get_boolean(parser, 'domains')
        self.roles = self._get_boolean(parser, 'roles')
        self.users = self._get_boolean(parser, 'users')
        self.projects = self._get_boolean(parser, 'projects')
        self.assignments = self._get_boolean(parser, 'assignments')

    @staticmethod
    def _get_boolean(parser, option, default=False):
        if parser.has_option('migrate', option):
            return parser.getboolean('migrate', option)
        return default


class HTTPServiceException(Exception):
    def __init__(self, code, explanation=None):
        self.code = code
        self.description = httplib.responses.get(code)
        self.explanation = explanation

    def __str__(self):
        if self.explanation is None:
            fmt = '%(code)s %(desc)s'
        else:
            fmt = '%(code)s %(desc)s: %(exp)s'
        return fmt % {'code': self.code,
                      'desc': self.description,
                      'exp': self.explanation}

    @property
    def is_unauthorized(self):
        return self.code == httplib.UNAUTHORIZED


class HTTPService(object):
    def __init__(self, auth_url):
        scheme, url, _, _, _, _ = urlparse.urlparse(auth_url)
        if ':' in url:
            server, port = url.split(':')
        else:
            server = url
            port = 5000
        if scheme.lower() == 'https':
            cls = httplib.HTTPSConnection
        else:
            cls = httplib.HTTPConnection
        self.conn = cls(server, port, timeout=600)

    def request(self, method, url, headers=None, body=None,
                ignore_result_body=False):
        if body is not None and not isinstance(body, basestring):
            body = json.dumps(body)
        self.conn.request(method, url, body, headers or {})

        response = self.conn.getresponse()
        code = response.status

        if code in (httplib.BAD_REQUEST, httplib.INTERNAL_SERVER_ERROR,
                    httplib.UNAUTHORIZED, httplib.FORBIDDEN, httplib.CONFLICT):
            log('%s, %s, %s, %s' % (method, url, headers, body))
            raise HTTPServiceException(code=code, explanation=response.read())
        if ignore_result_body:
            response.read()
        return response


class AuthService(HTTPService):
    def __init__(self, config):
        super(AuthService, self).__init__(config.auth_url)
        self.config = config
        self._auth_token = None

    def get_token(self):
        headers = {"Content-Type": "application/json"}
        body = {
            "auth": {
                "identity": {
                    "methods": [
                        "password"
                    ],
                    "password": {
                        "user": {
                            "name": self.config.username,
                            "domain": {
                                "name": self.config.domain
                            },
                            "password": self.config.password
                        }
                    }
                },
                "scope": {
                    "project": {
                        "domain": {
                            "name": self.config.domain
                        },
                        "name": self.config.project
                    }
                }
            }
        }
        response = self.request("POST", "/v3/auth/tokens", headers,
                                body, ignore_result_body=True)
        token = response.getheader('X-Subject-Token')
        log('Token: %s' % token)
        return token


class ProjectService(HTTPService):
    def __init__(self, config, filter_domains=None, rename_domains=None):
        super(ProjectService, self).__init__(config.auth_url)
        self.auth_service = AuthService(config)
        self.config = config
        self._auth_token = None
        self.domains = {}
        self.domains_name_id = {}
        self.projects = {}
        self.projects_name_id = {}
        self.users = {}
        self.user_name_id = {}
        self.roles = {}
        self.roles_name_id = {}
        self.assignments_domain_user = {}
        self.assignments_project_user = {}
        self.new_passwords = {}
        if filter_domains:
            self.filter_domains = {d.lower() for d in filter_domains}
        else:
            self.filter_domains = []
        if rename_domains:
            self.rename_domains = {}
            for d in rename_domains:
                old_name, new_name = d.split('=')
                self.rename_domains[old_name] = new_name
        else:
            self.rename_domains = {}

    def request(self, method, url, headers=None, body=None,
                ignore_result_body=False):
        if self._auth_token is None:
            self._auth_token = self.auth_service.get_token()
        if headers is None:
            headers = {}
        headers['x-auth-token'] = self._auth_token
        res = super(ProjectService, self).request(method, url, headers, body,
                                                  ignore_result_body)
        if not ignore_result_body:
            res = json.loads(res.read())
        return res

    @staticmethod
    def add_name_id(target, object_name, object_id):
        target[object_name] = object_id
        target[object_id] = object_name

    def get_projects(self, domain_id):
        log('Get projects for domain %s' % domain_id)
        url = '/v3/projects?domain_id=%s' % domain_id
        projects = {p['id']: p for p in self.request('GET', url)['projects']}
        log('Projects count: %s' % len(projects))
        return projects

    def get_domains(self):
        log('Get domains')
        url = '/v3/domains'
        domains = self.request('GET', url)['domains']
        log('Domains count: %s' % len(domains))
        return domains

    def get_users(self, domain_id):
        log('Get users for domain %s' % domain_id)
        url = '/v3/users?domain_id=%s' % domain_id
        users = self.request('GET', url)['users']
        log('Users count: %s' % len(users))
        return users

    def get_roles(self):
        log('Get roles')
        url = '/v3/roles'
        roles = self.request('GET', url)['roles']
        log('Roles count: %s' % len(roles))
        return roles

    def get_assignments_domain_user(self, domain_id, user_id):
        log('Get assignments for domain %s and user %s' % (domain_id, user_id))
        url = '/v3/domains/%s/users/%s/roles' % (domain_id, user_id)
        roles = self.request('GET', url)['roles']
        log('Assignments count: %s' % len(roles))
        return roles

    def get_assignments_project_user(self, project_id, user_id):
        log('Get assignments for project %s and user %s' % (project_id,
                                                            user_id))
        url = '/v3/projects/%s/users/%s/roles' % (project_id, user_id)
        roles = self.request('GET', url)['roles']
        log('Assignments count: %s' % len(roles))
        return roles

    def get_assignments(self, user_id):
        log('Get assignments for user %s' % (user_id))
        url = '/v3/role_assignments?user.id=%s' % user_id
        role_assignments = self.request('GET', url)['role_assignments']
        log('Assignments count: %s' % len(role_assignments))
        return role_assignments

    def read_info(self):
        log('Read info for url %s' % self.config.auth_url)
        for domain in self.get_domains():
            domain_id = domain['id']
            domain_name = domain['name']
            if (
                self.filter_domains and
                not (
                    domain_id.lower() in self.filter_domains or
                    domain_name.lower() in self.filter_domains
                )
            ):
                continue
            rec = {
                'id': domain_id,
            }
            data = copy.copy(domain)
            for key in ('id', 'links'):
                data.pop(key, None)
            domain_name = self.rename_domains.get(domain_name, domain_name)
            data['name'] = domain_name
            rec['data'] = data
            self.domains[domain_name] = rec

        for role in self.get_roles():
            rec = {
                'id': role['id']
            }
            data = copy.copy(role)
            for key in ('id', 'links'):
                data.pop(key, None)
            rec['data'] = data
            self.roles[role['name']] = rec
            self.add_name_id(self.roles_name_id, role['name'], rec['id'])

        for domain_name, domain in self.domains.items():
            domain_id = domain['id']
            self.add_name_id(self.domains_name_id, domain_name, domain_id)

            projects = self.get_projects(domain_id)
            for project_id, project in projects.items():
                names = [project['name']]
                parent_id = project['parent_id']
                if parent_id == project_id or parent_id == domain_id:
                    parent_id = None
                while parent_id:
                    pr = projects[parent_id]
                    names.append(pr['name'])
                    parent_id = pr['parent_id']
                    if parent_id == pr['id']:
                        break
                names.append(domain_name)
                rec = {
                    'id': project_id,
                    'name': '/'.join([domain_name, project['name']])
                }
                data = copy.copy(project)
                data['parent_id'] = parent_id
                for key in ('id', 'links'):
                    data.pop(key, None)
                rec['data'] = data
                project_name = '/'.join(names[::-1])
                self.projects[project_name] = rec
                self.add_name_id(self.projects_name_id, project_name,
                                 project_id)

            for user in self.get_users(domain_id):
                user_id = user['id']
                rec = {
                    'id': user_id
                }
                data = copy.copy(user)
                for key in ('id', 'links', 'password_expires_at'):
                    data.pop(key, None)
                rec['data'] = data
                user_name = '/'.join([domain_name, user['name']])
                self.users[user_name] = rec
                self.add_name_id(self.user_name_id, user_name,
                                 user_id)

                for assignment in self.get_assignments(user_id):
                    if 'domain' in assignment['scope']:
                        rec = {
                            'domain_id': assignment['scope']['domain']['id'],
                            'user_id': user_id,
                            'role_id': assignment['role']['id']
                        }

                        assignment_name = '/'.join([
                            domain_name,
                            user['name'],
                            self.roles_name_id[rec['role_id']]
                        ])
                        self.assignments_domain_user[assignment_name] = rec
                    elif 'project' in assignment['scope']:
                        rec = {
                            'project_id': assignment['scope']['project']['id'],
                            'user_id': user_id,
                            'role_id': assignment['role']['id']
                        }

                        assignment_name = '/'.join([
                            domain_name,
                            self.projects_name_id[rec['project_id']],
                            user['name'],
                            self.roles_name_id[rec['role_id']]
                        ])
                        self.assignments_project_user[assignment_name] = rec

    def create_domain(self, data):
        url = "/v3/domains"
        return self.request('POST', url, body={'domain': data})['domain']

    def create_role(self, data):
        url = "/v3/roles"
        return self.request('POST', url, body={'role': data})['role']

    def create_user(self, data):
        url = "/v3/users"
        return self.request('POST', url, body={'user': data})['user']

    def create_project(self, data):
        url = "/v3/projects"
        return self.request('POST', url, body={'project': data})['project']

    def create_assignments_domain_user(self, domain_id, user_id, role_id):
        url = '/v3/domains/%s/users/%s/roles/%s' % (domain_id, user_id,
                                                    role_id)
        self.request('PUT', url, ignore_result_body=True)

    def create_assignments_project_user(self, project_id, user_id, role_id):
        url = '/v3/projects/%s/users/%s/roles/%s' % (project_id, user_id,
                                                     role_id)
        self.request('PUT', url, ignore_result_body=True)


SYMBOLS = string.ascii_letters + string.digits


def generate_password():
    return ''.join(random.choice(SYMBOLS) for _ in range(20))


def get_difference(src, dst):
    res = {
        'domains': [],
        'projects': [],
        'users': [],
        'roles': [],
        'assignments_domain_user': [],
        'assignments_project_user': []
    }
    for name in src.domains:
        if name not in dst.domains:
            res['domains'].append(name)
    for name in src.projects:
        if name not in dst.projects:
            res['projects'].append(name)
    for name in src.users:
        if name not in dst.users:
            res['users'].append(name)
    for name in src.roles:
        if name not in dst.roles:
            res['roles'].append(name)
    for name in src.assignments_domain_user:
        if name not in dst.assignments_domain_user:
            res['assignments_domain_user'].append(name)
    for name in src.assignments_project_user:
        if name not in dst.assignments_project_user:
            res['assignments_project_user'].append(name)

    return res


def migrate(src, dst, config):
    diff = get_difference(src, dst)
    res = {
        's': collections.defaultdict(list),
        'f': collections.defaultdict(list)
    }
    if config.domains:
        log('Migrate domains')
    for name in diff['domains']:
        if config.domains:
            data = src.domains[name]['data']
            rec = dst.create_domain(data)
            dst.add_name_id(dst.domains_name_id, name, rec['id'])
            res['s']['domains'].append(name)
        else:
            res['f']['domains'].append(name)

    if config.roles:
        log('Migrate roles')
    for name in diff['roles']:
        if config.roles:
            data = src.roles[name]['data']
            rec = dst.create_role(data)
            dst.add_name_id(dst.roles_name_id, name, rec['id'])
            res['s']['roles'].append(name)
        else:
            res['f']['roles'].append(name)

    if config.projects:
        log('Migrate projects')
    for name in sorted(diff['projects']):
        if config.projects:
            data = src.projects[name]['data']
            src_domain_name = src.domains_name_id[data['domain_id']]
            dst_domain_id = dst.domains_name_id.get(src_domain_name)
            if dst_domain_id is None:
                res['f']['projects'].append(name)
                continue
            parent_id = data['parent_id']
            if parent_id is not None:
                if parent_id == data['domain_id']:
                    dst_parent_id = dst_domain_id
                else:
                    src_parent_name = src.projects_name_id[parent_id]
                    dst_parent_id = dst.projects_name_id.get(src_parent_name)
                    if dst_parent_id is None:
                        res['f']['projects'].append(name)
                        continue
                data['parent_id'] = dst_parent_id
            data['domain_id'] = dst_domain_id
            rec = dst.create_project(data)
            dst.add_name_id(dst.projects_name_id, name, rec['id'])
            res['s']['projects'].append(name)
        else:
            res['f']['projects'].append(name)

    if config.users:
        log('Migrate users')
    for name in diff['users']:
        if config.users:
            data = src.users[name]['data']
            src_domain_name = src.domains_name_id[data['domain_id']]
            dst_domain_id = dst.domains_name_id.get(src_domain_name)
            if dst_domain_id is None:
                res['f']['users'].append(name)
                continue
            data['domain_id'] = dst_domain_id
            if 'default_project_id' in data:
                src_default_project_name = src.projects_name_id[
                    data['default_project_id']
                ]
                dst_default_project_id = dst.projects_name_id.get(
                    src_default_project_name
                )
                data['default_project_id'] = dst_default_project_id
            password = generate_password()
            data['password'] = password
            rec = dst.create_user(data)
            dst.add_name_id(dst.user_name_id, name, rec['id'])
            dst.new_passwords[name] = password
            res['s']['users'].append(name)
        else:
            res['f']['users'].append(name)

    if config.assignments:
        log('Migrate assignments for domains and users')
    for name in diff['assignments_domain_user']:
        if config.assignments:
            data = src.assignments_domain_user[name]
            src_role_name = src.roles_name_id[data['role_id']]
            dst_role_id = dst.roles_name_id.get(src_role_name)
            src_user_name = src.user_name_id[data['user_id']]
            dst_user_id = dst.user_name_id.get(src_user_name)
            src_domain_name = src.domains_name_id[data['domain_id']]
            dst_domain_id = dst.domains_name_id.get(src_domain_name)
            if any((dst_role_id is None,
                    dst_user_id is None,
                    dst_domain_id is None)):
                res['f']['assignments_domain_user'].append(name)
            dst.create_assignments_domain_user(dst_domain_id, dst_user_id,
                                               dst_role_id)
            res['s']['assignments_domain_user'].append(name)
        else:
            res['f']['assignments_domain_user'].append(name)

    if config.assignments:
        log('Migrate assignments for projects and users')

    for name in diff['assignments_project_user']:
        if config.assignments:
            data = src.assignments_project_user[name]
            src_role_name = src.roles_name_id[data['role_id']]
            dst_role_id = dst.roles_name_id.get(src_role_name)
            src_user_name = src.user_name_id[data['user_id']]
            dst_user_id = dst.user_name_id.get(src_user_name)
            src_project_name = src.projects_name_id[data['project_id']]
            dst_project_id = dst.projects_name_id.get(src_project_name)
            if any((dst_role_id is None,
                    dst_user_id is None,
                    dst_project_id is None)):
                res['f']['assignments_project_user'].append(name)
            dst.create_assignments_project_user(dst_project_id, dst_user_id,
                                                dst_role_id)
            res['s']['assignments_project_user'].append(name)
        else:
            res['f']['assignments_project_user'].append(name)

    return res


def print_diff(diff, src, dst):
    if diff['domains']:
        print 'Domains:'
        print '\n'.join('  - %s (%s)' % (n, src.domains[n]['id'])
                        for n in diff['domains'])
    if diff['projects']:
        print 'Projects (Domain/Name):'
        print '\n'.join('  - %s (%s)' % (src.projects[n]['name'],
                                         src.projects[n]['id'])
                        for n in diff['projects'])
    if diff['users']:
        print 'Users (Domain/Name[:new password]):'
        for n in diff['users']:
            if n in dst.new_passwords:
                user_name = '%s:%s' % (n, dst.new_passwords[n])
            else:
                user_name = n
            print '  - %s (%s)' % (user_name, src.users[n]['id'])
    if diff['roles']:
        print 'Roles (Domain/Name):'
        print '\n'.join('  - %s (%s)' % (n, src.roles[n]['id'])
                        for n in diff['roles'])
    if diff['assignments_domain_user']:
        print 'Role assignments for a user on a domain (Domain/User/Role):'
        print '\n'.join('  - %s (%s)' % (
            n, src.assignments_domain_user[n]['role_id']
        ) for n in diff['assignments_domain_user'])
    if diff['assignments_project_user']:
        print 'Role assignments for a user on a project ' \
              '(Domain/Project/User/Role):'
        print '\n'.join('  - %s (%s)' % (
            n, src.assignments_project_user[n]['role_id']
        ) for n in diff['assignments_project_user'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('config', type=argparse.FileType('r'))
    parser.add_argument('-d', '--filter_domain', action='append', default=[],
                        dest='filter_domains')
    parser.add_argument('-r', '--rename_domain', action='append', default=[],
                        dest='rename_domains')
    parser.add_argument('--migrate', action='store_true', default=False)
    args = parser.parse_args()

    cfg_parser = configparser.ConfigParser()
    cfg_parser.readfp(args.config)

    cfg_src = Config(dict(cfg_parser.items('source')))
    cfg_dst = Config(dict(cfg_parser.items('dest')))
    pr_src = ProjectService(cfg_src, args.filter_domains, args.rename_domains)
    pr_src.read_info()
    pr_dst = ProjectService(cfg_dst, pr_src.domains.keys())
    pr_dst.read_info()
    if args.migrate:
        diff = migrate(pr_src, pr_dst, MigrationConfig(cfg_parser))
        if diff['s']:
            print "The following objects have been successfully migrated:"
            print_diff(diff['s'], pr_src, pr_dst)
        if diff['f']:
            print "The following objects are not migrated:"
            print_diff(diff['f'], pr_src, pr_dst)

    else:
        diff = get_difference(pr_src, pr_dst)
        print_diff(diff, pr_src, pr_src)


if __name__ == '__main__':
    main()
