name             'eol-iptables-wrapper'
maintainer       'Marine Biological Laboratory'
maintainer_email 'jrice@eol.org'
license          'MIT'
description      'Installs/Configures iptables'
long_description IO.read(File.join(File.dirname(__FILE__), 'README.md'))
depends          'simple_iptables', '~> 0.7.1'
attribute        'iptables/allow_protocols',
                   :display_name => "Allowed Protocols",
                   :description => "List of the protocols allowed in IP Tables",
                   :choice => %w(http https http_8080 http_8081 http_8082
                                 http_8083 rsync redis memcached solr rabbit-mq
                                 node.js mysql sysopia virtuoso),
                   :type => "string",
                   :required => "required"

version          '0.1.5'
