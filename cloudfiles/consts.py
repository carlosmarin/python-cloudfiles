""" See COPYING for license information. """

__version__ = "1.7.12-multi-region"
user_agent = "python-cloudfiles/%s" % __version__
us_authurl = 'https://identity.api.rackspacecloud.com/v2.0/tokens'
uk_authurl = 'https://lon.identity.api.rackspacecloud.com/v2.0/tokens'
default_authurl = us_authurl
object_store_service_name='cloudFiles'
object_cdn_service_name='cloudFilesCDN'
default_cdn_ttl = 86400
cdn_log_retention = False

meta_name_limit = 128
meta_value_limit = 256
object_name_limit = 1024
container_name_limit = 256
