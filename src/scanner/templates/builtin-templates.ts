import type { VulnTemplate } from './engine.js';

// ═══════════════════════════════════════════════════════════════════
// Built-in vulnerability templates — hardcoded TypeScript objects.
// No YAML parsing dependency required.
//
// Categories:
//   1. Exposed Admin Panels (15)
//   2. Debug / Info Disclosure (15)
//   3. Default Credentials (10)
//   4. Known Misconfigurations (10+)
// ═══════════════════════════════════════════════════════════════════

// ─── 1. Exposed Admin Panels ─────────────────────────────────────

const adminPanels: VulnTemplate[] = [
  {
    id: 'wp-admin-exposed',
    info: {
      name: 'WordPress Admin Panel Exposed',
      severity: 'medium',
      description: 'WordPress admin login page is publicly accessible. This can be used as a target for brute-force attacks.',
      tags: ['panel', 'wordpress'],
      reference: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'],
      cwe: 'CWE-200',
    },
    match: { tech: ['wordpress'] },
    requests: [{
      method: 'GET',
      path: '/wp-admin/',
      matchers: [
        { type: 'status', status: [200, 302] },
        { type: 'body', words: ['wp-login'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'wp-login-exposed',
    info: {
      name: 'WordPress Login Page Exposed',
      severity: 'info',
      description: 'WordPress wp-login.php is accessible. Consider restricting access via IP allowlist or two-factor authentication.',
      tags: ['panel', 'wordpress'],
      cwe: 'CWE-200',
    },
    match: { tech: ['wordpress'] },
    requests: [{
      method: 'GET',
      path: '/wp-login.php',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['user_login', 'user_pass'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'drupal-admin-exposed',
    info: {
      name: 'Drupal Admin Panel Exposed',
      severity: 'medium',
      description: 'Drupal admin login page is publicly accessible.',
      tags: ['panel', 'drupal'],
      cwe: 'CWE-200',
    },
    match: { tech: ['drupal'] },
    requests: [{
      method: 'GET',
      path: '/user/login',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['drupal', 'user-login-form'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'django-admin-exposed',
    info: {
      name: 'Django Admin Panel Exposed',
      severity: 'medium',
      description: 'Django admin interface is publicly accessible. This exposes the authentication endpoint and may reveal model structure.',
      tags: ['panel', 'django', 'python'],
      cwe: 'CWE-200',
    },
    match: { tech: ['django', 'python'] },
    requests: [{
      method: 'GET',
      path: '/admin/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['django', 'administration'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'phpmyadmin-exposed',
    info: {
      name: 'phpMyAdmin Exposed',
      severity: 'high',
      description: 'phpMyAdmin is publicly accessible. This provides direct database management access if not properly secured.',
      tags: ['panel', 'php', 'database'],
      reference: ['https://www.phpmyadmin.net/security/'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/phpmyadmin/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['phpmyadmin'] },
        { type: 'regex', regex: '(?:phpMyAdmin|pma_username|login_form)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'adminer-exposed',
    info: {
      name: 'Adminer Database Manager Exposed',
      severity: 'high',
      description: 'Adminer database management tool is publicly accessible.',
      tags: ['panel', 'php', 'database'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/adminer.php',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['adminer'] },
        { type: 'regex', regex: '(?:adminer|auth\\[driver\\]|auth\\[server\\])' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'kibana-exposed',
    info: {
      name: 'Kibana Dashboard Exposed',
      severity: 'high',
      description: 'Kibana dashboard is publicly accessible. This may expose log data, indices, and internal infrastructure details.',
      tags: ['panel', 'elastic', 'devtools'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/app/kibana',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['kibana'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'grafana-exposed',
    info: {
      name: 'Grafana Dashboard Exposed',
      severity: 'medium',
      description: 'Grafana dashboard is publicly accessible. May expose internal metrics and infrastructure data.',
      tags: ['panel', 'grafana', 'devtools'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/login',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['grafana'] },
        { type: 'regex', regex: '(?:grafana|Grafana)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'jenkins-exposed',
    info: {
      name: 'Jenkins CI Exposed',
      severity: 'high',
      description: 'Jenkins CI/CD dashboard is publicly accessible. This may allow unauthenticated access to build configurations and secrets.',
      tags: ['panel', 'jenkins', 'devtools'],
      reference: ['https://www.jenkins.io/doc/book/security/'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/',
      matchers: [
        { type: 'status', status: [200, 403] },
        { type: 'header', header: 'x-jenkins' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'gitlab-exposed',
    info: {
      name: 'GitLab Instance Exposed',
      severity: 'medium',
      description: 'GitLab instance is publicly accessible. Check that registration is disabled and access controls are properly configured.',
      tags: ['panel', 'gitlab', 'devtools'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/users/sign_in',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['gitlab'] },
        { type: 'regex', regex: '(?:GitLab|gitlab-ce|gitlab-ee)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'portainer-exposed',
    info: {
      name: 'Portainer Container Manager Exposed',
      severity: 'high',
      description: 'Portainer Docker/Kubernetes management interface is publicly accessible.',
      tags: ['panel', 'docker', 'devtools'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/api/status',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['version'] },
        { type: 'regex', regex: '"Version"\\s*:' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'webmin-exposed',
    info: {
      name: 'Webmin Panel Exposed',
      severity: 'high',
      description: 'Webmin system administration panel is publicly accessible.',
      tags: ['panel', 'linux'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['webmin'] },
        { type: 'regex', regex: '(?:Webmin|webmin_search)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'couchdb-fauxton-exposed',
    info: {
      name: 'CouchDB Fauxton UI Exposed',
      severity: 'high',
      description: 'CouchDB Fauxton web UI is publicly accessible, potentially allowing database management.',
      tags: ['panel', 'database', 'couchdb'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/_utils/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['fauxton'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'solr-admin-exposed',
    info: {
      name: 'Apache Solr Admin Exposed',
      severity: 'high',
      description: 'Apache Solr admin interface is publicly accessible. This may expose search indices and configuration.',
      tags: ['panel', 'solr', 'java'],
      cwe: 'CWE-200',
    },
    match: { tech: ['java', 'solr'] },
    requests: [{
      method: 'GET',
      path: '/solr/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['solr'] },
        { type: 'regex', regex: '(?:Solr Admin|solr-admin)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'joomla-admin-exposed',
    info: {
      name: 'Joomla Admin Panel Exposed',
      severity: 'medium',
      description: 'Joomla administrator login page is publicly accessible.',
      tags: ['panel', 'joomla', 'php'],
      cwe: 'CWE-200',
    },
    match: { tech: ['joomla'] },
    requests: [{
      method: 'GET',
      path: '/administrator/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['joomla'] },
        { type: 'regex', regex: '(?:com_login|mod-login)' },
      ],
      matchCondition: 'and',
    }],
  },
];

// ─── 2. Debug / Info Disclosure ──────────────────────────────────

const debugDisclosure: VulnTemplate[] = [
  {
    id: 'phpinfo-exposed',
    info: {
      name: 'phpinfo() Page Exposed',
      severity: 'medium',
      description: 'phpinfo() is publicly accessible, exposing server configuration, environment variables, and loaded modules.',
      tags: ['debug', 'php', 'disclosure'],
      reference: ['https://www.php.net/manual/en/function.phpinfo.php'],
      cwe: 'CWE-200',
    },
    match: { tech: ['php'] },
    requests: [{
      method: 'GET',
      path: '/phpinfo.php',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['php version', 'configuration'] },
        { type: 'regex', regex: '(?:phpinfo\\(\\)|PHP Version|PHP Credits)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'env-file-exposed',
    info: {
      name: '.env File Exposed',
      severity: 'critical',
      description: 'Environment configuration file (.env) is publicly accessible. This typically contains database credentials, API keys, and other secrets.',
      tags: ['config', 'exposure', 'disclosure'],
      reference: ['https://owasp.org/www-project-web-security-testing-guide/'],
      cwe: 'CWE-538',
    },
    requests: [{
      method: 'GET',
      path: '/.env',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:DB_PASSWORD|DATABASE_URL|API_KEY|SECRET_KEY|APP_KEY|MAIL_PASSWORD|AWS_SECRET)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'apache-server-status',
    info: {
      name: 'Apache server-status Exposed',
      severity: 'medium',
      description: 'Apache server-status page is publicly accessible, exposing active connections, request URLs, and client IPs.',
      tags: ['debug', 'apache', 'disclosure'],
      cwe: 'CWE-200',
    },
    match: { tech: ['apache'] },
    requests: [{
      method: 'GET',
      path: '/server-status',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['apache', 'server status'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'spring-actuator-env',
    info: {
      name: 'Spring Boot Actuator /env Exposed',
      severity: 'high',
      description: 'Spring Boot Actuator environment endpoint is publicly accessible, exposing configuration properties and potential secrets.',
      tags: ['debug', 'java', 'spring', 'disclosure'],
      reference: ['https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html'],
      cwe: 'CWE-200',
    },
    match: { tech: ['java', 'spring'] },
    requests: [{
      method: 'GET',
      path: '/actuator/env',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:"propertySources"|"activeProfiles"|"systemProperties")' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'spring-actuator-health',
    info: {
      name: 'Spring Boot Actuator Health Exposed',
      severity: 'low',
      description: 'Spring Boot Actuator health endpoint is publicly accessible, exposing application health details and component status.',
      tags: ['debug', 'java', 'spring'],
      cwe: 'CWE-200',
    },
    match: { tech: ['java', 'spring'] },
    requests: [{
      method: 'GET',
      path: '/actuator/health',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"status"\\s*:\\s*"(?:UP|DOWN)"' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'spring-actuator-mappings',
    info: {
      name: 'Spring Boot Actuator Mappings Exposed',
      severity: 'medium',
      description: 'Spring Boot Actuator mappings endpoint reveals all URL mappings and controller methods.',
      tags: ['debug', 'java', 'spring', 'disclosure'],
      cwe: 'CWE-200',
    },
    match: { tech: ['java', 'spring'] },
    requests: [{
      method: 'GET',
      path: '/actuator/mappings',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:"dispatcherServlets"|"servletFilters"|"handler")' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'laravel-telescope-exposed',
    info: {
      name: 'Laravel Telescope Debug Tool Exposed',
      severity: 'high',
      description: 'Laravel Telescope is publicly accessible, exposing request/response data, queries, logs, and environment information.',
      tags: ['debug', 'php', 'laravel', 'devtools'],
      cwe: 'CWE-200',
    },
    match: { tech: ['laravel', 'php'] },
    requests: [{
      method: 'GET',
      path: '/telescope',
      matchers: [
        { type: 'status', status: [200, 302] },
        { type: 'regex', regex: '(?:telescope|Laravel Telescope)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'laravel-horizon-exposed',
    info: {
      name: 'Laravel Horizon Queue Dashboard Exposed',
      severity: 'medium',
      description: 'Laravel Horizon queue management dashboard is publicly accessible.',
      tags: ['debug', 'php', 'laravel', 'devtools'],
      cwe: 'CWE-200',
    },
    match: { tech: ['laravel', 'php'] },
    requests: [{
      method: 'GET',
      path: '/horizon',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['horizon'] },
        { type: 'regex', regex: '(?:Laravel Horizon|horizon-config)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'rails-info-routes',
    info: {
      name: 'Rails Routes Info Exposed',
      severity: 'medium',
      description: 'Ruby on Rails routing information page is publicly accessible, exposing all application routes and controllers.',
      tags: ['debug', 'ruby', 'rails', 'disclosure'],
      cwe: 'CWE-200',
    },
    match: { tech: ['ruby', 'rails'] },
    requests: [{
      method: 'GET',
      path: '/rails/info/routes',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['routes'] },
        { type: 'regex', regex: '(?:rails|controller|action|prefix|verb)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'swagger-ui-exposed',
    info: {
      name: 'Swagger/OpenAPI Documentation Exposed',
      severity: 'low',
      description: 'Swagger UI or OpenAPI documentation is publicly accessible, revealing all API endpoints, parameters, and schemas.',
      tags: ['debug', 'disclosure', 'devtools'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/swagger-ui.html',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:swagger-ui|Swagger UI|swagger-initializer)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'swagger-json-exposed',
    info: {
      name: 'Swagger/OpenAPI JSON Spec Exposed',
      severity: 'low',
      description: 'Swagger/OpenAPI JSON specification is publicly accessible, revealing complete API structure.',
      tags: ['debug', 'disclosure', 'devtools'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/swagger.json',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"(?:swagger|openapi)"\\s*:\\s*"' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'graphql-playground-exposed',
    info: {
      name: 'GraphQL Playground Exposed',
      severity: 'low',
      description: 'GraphQL playground/GraphiQL is publicly accessible, allowing interactive query execution.',
      tags: ['debug', 'graphql', 'devtools'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/graphiql',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:graphiql|GraphiQL|graphql-playground)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'git-head-exposed',
    info: {
      name: 'Git Repository (.git/HEAD) Exposed',
      severity: 'high',
      description: 'Git repository metadata is publicly accessible. Attackers can potentially reconstruct the full source code using tools like git-dumper.',
      tags: ['exposure', 'config', 'disclosure'],
      reference: ['https://owasp.org/www-project-web-security-testing-guide/'],
      cwe: 'CWE-538',
    },
    requests: [{
      method: 'GET',
      path: '/.git/HEAD',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '^ref: refs/' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'svn-entries-exposed',
    info: {
      name: 'SVN Repository (.svn/entries) Exposed',
      severity: 'high',
      description: 'SVN repository metadata is publicly accessible. May allow attackers to reconstruct source code.',
      tags: ['exposure', 'config', 'disclosure'],
      cwe: 'CWE-538',
    },
    requests: [{
      method: 'GET',
      path: '/.svn/entries',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['dir'] },
        // Must NOT be an error page
        { type: 'body', words: ['not found'], negative: true },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'ds-store-exposed',
    info: {
      name: 'macOS .DS_Store File Exposed',
      severity: 'low',
      description: '.DS_Store file is publicly accessible, potentially revealing directory structure and filenames.',
      tags: ['exposure', 'config'],
      cwe: 'CWE-538',
    },
    requests: [{
      method: 'GET',
      path: '/.DS_Store',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: 'Bud1' },
      ],
      matchCondition: 'and',
    }],
  },
];

// ─── 3. Default Credentials ──────────────────────────────────────

const defaultCredentials: VulnTemplate[] = [
  {
    id: 'tomcat-manager-default',
    info: {
      name: 'Apache Tomcat Manager Default Credentials',
      severity: 'critical',
      description: 'Apache Tomcat Manager is accessible with default credentials (tomcat:tomcat). This allows WAR file deployment and complete server compromise.',
      tags: ['default-credentials', 'java', 'tomcat'],
      reference: ['https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html'],
      cwe: 'CWE-798',
    },
    match: { tech: ['tomcat', 'java'] },
    requests: [{
      method: 'GET',
      path: '/manager/html',
      headers: {
        'Authorization': 'Basic dG9tY2F0OnRvbWNhdA==', // tomcat:tomcat
      },
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['tomcat web application manager'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'tomcat-manager-s3cret',
    info: {
      name: 'Apache Tomcat Manager Known Weak Credentials',
      severity: 'critical',
      description: 'Apache Tomcat Manager is accessible with well-known weak credentials (tomcat:s3cret).',
      tags: ['default-credentials', 'java', 'tomcat'],
      cwe: 'CWE-798',
    },
    match: { tech: ['tomcat', 'java'] },
    requests: [{
      method: 'GET',
      path: '/manager/html',
      headers: {
        'Authorization': 'Basic dG9tY2F0OnMzY3JldA==', // tomcat:s3cret
      },
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['tomcat web application manager'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'jenkins-no-auth',
    info: {
      name: 'Jenkins No Authentication Required',
      severity: 'critical',
      description: 'Jenkins is accessible without any authentication, allowing anyone to view/create/execute builds and access credentials.',
      tags: ['default-credentials', 'jenkins', 'auth-bypass'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/manage',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['manage jenkins'] },
        // Must NOT be redirected to login
        { type: 'body', words: ['sign in'], negative: true },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'jenkins-script-console',
    info: {
      name: 'Jenkins Script Console Accessible',
      severity: 'critical',
      description: 'Jenkins Groovy script console is accessible. This allows arbitrary code execution on the Jenkins server.',
      tags: ['default-credentials', 'jenkins', 'auth-bypass'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/script',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['script console'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'mongodb-no-auth',
    info: {
      name: 'MongoDB HTTP Interface No Auth',
      severity: 'critical',
      description: 'MongoDB HTTP interface is accessible without authentication, exposing database contents and server information.',
      tags: ['default-credentials', 'database', 'mongodb'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: 'It looks like you are trying to access MongoDB' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'elasticsearch-no-auth',
    info: {
      name: 'Elasticsearch No Authentication',
      severity: 'high',
      description: 'Elasticsearch is accessible without authentication, exposing cluster health, indices, and data.',
      tags: ['default-credentials', 'database', 'elastic'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"cluster_name"\\s*:' },
        { type: 'regex', regex: '"tagline"\\s*:\\s*"You Know, for Search"' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'elasticsearch-indices',
    info: {
      name: 'Elasticsearch Indices Listing Accessible',
      severity: 'high',
      description: 'Elasticsearch index listing is accessible without authentication, revealing all stored data indices.',
      tags: ['default-credentials', 'database', 'elastic'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/_cat/indices',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:green|yellow|red)\\s+\\w+' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'grafana-default-admin',
    info: {
      name: 'Grafana Default Admin Credentials',
      severity: 'critical',
      description: 'Grafana is accessible with default credentials (admin:admin). This grants full administrator access.',
      tags: ['default-credentials', 'grafana'],
      cwe: 'CWE-798',
    },
    requests: [{
      method: 'POST',
      path: '/api/login',
      headers: { 'Content-Type': 'application/json' },
      body: '{"user":"admin","password":"admin"}',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"message"\\s*:\\s*"Logged in"' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'rabbitmq-default-creds',
    info: {
      name: 'RabbitMQ Management Default Credentials',
      severity: 'critical',
      description: 'RabbitMQ management interface is accessible with default credentials (guest:guest).',
      tags: ['default-credentials', 'rabbitmq'],
      cwe: 'CWE-798',
    },
    requests: [{
      method: 'GET',
      path: '/api/whoami',
      headers: {
        'Authorization': 'Basic Z3Vlc3Q6Z3Vlc3Q=', // guest:guest
      },
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"name"\\s*:\\s*"guest"' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'consul-no-auth',
    info: {
      name: 'HashiCorp Consul No Authentication',
      severity: 'high',
      description: 'HashiCorp Consul API is accessible without authentication, exposing service mesh configuration and KV store.',
      tags: ['default-credentials', 'consul', 'auth-bypass'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/v1/agent/self',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"Config"\\s*:' },
      ],
      matchCondition: 'and',
    }],
  },
];

// ─── 4. Known Misconfigurations ──────────────────────────────────

const knownMisconfigs: VulnTemplate[] = [
  {
    id: 'cors-wildcard-with-creds',
    info: {
      name: 'CORS Wildcard with Credentials',
      severity: 'high',
      description: 'Server returns Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true. This is a dangerous misconfiguration that may allow cross-origin data theft.',
      tags: ['misconfig', 'cors'],
      cwe: 'CWE-346',
    },
    requests: [{
      method: 'GET',
      path: '/',
      headers: { 'Origin': 'https://evil.com' },
      matchers: [
        { type: 'header', header: 'access-control-allow-origin', value: '*' },
        { type: 'header', header: 'access-control-allow-credentials', value: 'true' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'cors-origin-reflection',
    info: {
      name: 'CORS Origin Reflection',
      severity: 'high',
      description: 'Server reflects the Origin header in Access-Control-Allow-Origin, indicating it trusts any origin. Combined with credentials, this enables cross-origin data theft.',
      tags: ['misconfig', 'cors'],
      cwe: 'CWE-346',
    },
    requests: [{
      method: 'GET',
      path: '/',
      headers: { 'Origin': 'https://evil-attacker.com' },
      matchers: [
        { type: 'header', header: 'access-control-allow-origin', value: 'https://evil-attacker.com' },
        { type: 'header', header: 'access-control-allow-credentials', value: 'true' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'trace-method-enabled',
    info: {
      name: 'HTTP TRACE Method Enabled',
      severity: 'low',
      description: 'The HTTP TRACE method is enabled on the server. This can be exploited for Cross-Site Tracing (XST) attacks to steal credentials.',
      tags: ['misconfig', 'headers'],
      reference: ['https://owasp.org/www-community/attacks/Cross_Site_Tracing'],
      cwe: 'CWE-693',
    },
    requests: [{
      method: 'GET',
      path: '/',
      headers: { 'X-Custom-Header': 'secbot-trace-test' },
      matchers: [
        { type: 'status', status: [200] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'x-powered-by-exposed',
    info: {
      name: 'X-Powered-By Header Exposes Technology',
      severity: 'info',
      description: 'The X-Powered-By response header exposes the server technology and version. Remove this header to reduce information leakage.',
      tags: ['misconfig', 'headers', 'disclosure'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/',
      matchers: [
        { type: 'header', header: 'x-powered-by' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'directory-listing-root',
    info: {
      name: 'Directory Listing Enabled on Root',
      severity: 'medium',
      description: 'Directory listing is enabled on the web root, exposing all files and folders to anyone.',
      tags: ['misconfig', 'listing', 'disclosure'],
      cwe: 'CWE-548',
    },
    requests: [{
      method: 'GET',
      path: '/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:Index of /|Directory listing for /|<title>Directory: /)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'directory-listing-uploads',
    info: {
      name: 'Directory Listing on Uploads Folder',
      severity: 'medium',
      description: 'Directory listing is enabled on /uploads, potentially exposing uploaded files.',
      tags: ['misconfig', 'listing', 'disclosure'],
      cwe: 'CWE-548',
    },
    requests: [{
      method: 'GET',
      path: '/uploads/',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:Index of /uploads|Directory listing for /uploads)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'wordpress-xmlrpc',
    info: {
      name: 'WordPress XML-RPC Enabled',
      severity: 'medium',
      description: 'WordPress XML-RPC interface is enabled. This can be abused for brute-force attacks, DDoS amplification, and SSRF.',
      tags: ['misconfig', 'wordpress'],
      reference: ['https://kinsta.com/blog/xmlrpc-php/'],
      cwe: 'CWE-16',
    },
    match: { tech: ['wordpress'] },
    requests: [{
      method: 'POST',
      path: '/xmlrpc.php',
      headers: { 'Content-Type': 'text/xml' },
      body: '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'body', words: ['methodresponse'] },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'wp-user-enum',
    info: {
      name: 'WordPress User Enumeration via REST API',
      severity: 'low',
      description: 'WordPress REST API exposes user information, allowing enumeration of usernames.',
      tags: ['misconfig', 'wordpress', 'disclosure'],
      cwe: 'CWE-200',
    },
    match: { tech: ['wordpress'] },
    requests: [{
      method: 'GET',
      path: '/wp-json/wp/v2/users',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"slug"\\s*:' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'debug-header-exposed',
    info: {
      name: 'Debug/Version Headers Exposed',
      severity: 'info',
      description: 'Server exposes debug-related headers (X-Debug-Token, X-Debug-Token-Link) that may reveal internal information.',
      tags: ['misconfig', 'headers', 'debug'],
      cwe: 'CWE-200',
    },
    requests: [{
      method: 'GET',
      path: '/',
      matchers: [
        { type: 'header', header: 'x-debug-token' },
      ],
      matchCondition: 'or',
    }],
  },
  {
    id: 'wp-debug-log-exposed',
    info: {
      name: 'WordPress Debug Log Exposed',
      severity: 'high',
      description: 'WordPress debug.log is publicly accessible, potentially exposing PHP errors, stack traces, and sensitive data.',
      tags: ['config', 'wordpress', 'disclosure'],
      cwe: 'CWE-532',
    },
    match: { tech: ['wordpress'] },
    requests: [{
      method: 'GET',
      path: '/wp-content/debug.log',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '(?:PHP (?:Fatal|Warning|Notice|Deprecated)|Stack trace)' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'docker-api-exposed',
    info: {
      name: 'Docker API Exposed Without Auth',
      severity: 'critical',
      description: 'Docker Engine API is exposed without authentication. This allows complete container management and host compromise.',
      tags: ['misconfig', 'docker', 'auth-bypass'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/v1.41/containers/json',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '\\[.*"Id"\\s*:' },
      ],
      matchCondition: 'and',
    }],
  },
  {
    id: 'kubernetes-api-exposed',
    info: {
      name: 'Kubernetes API Server Exposed',
      severity: 'critical',
      description: 'Kubernetes API server is accessible, potentially allowing cluster enumeration or manipulation.',
      tags: ['misconfig', 'kubernetes', 'auth-bypass'],
      cwe: 'CWE-306',
    },
    requests: [{
      method: 'GET',
      path: '/api/v1/namespaces',
      matchers: [
        { type: 'status', status: [200] },
        { type: 'regex', regex: '"kind"\\s*:\\s*"NamespaceList"' },
      ],
      matchCondition: 'and',
    }],
  },
];

// ─── Export All Templates ────────────────────────────────────────

export const BUILTIN_TEMPLATES: VulnTemplate[] = [
  ...adminPanels,
  ...debugDisclosure,
  ...defaultCredentials,
  ...knownMisconfigs,
];
