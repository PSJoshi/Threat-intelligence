#!/usr/bin/env python
import requests
from requests_toolbelt.auth.http_proxy_digest import HTTPProxyDigestAuth
import logging
import sys
import traceback
import re
from utils.manage_elasticsearch import Manage_elasticsearch
import pycurl
import StringIO

# set up rotating file handler
#logging.basicConfig(level=logging.INFO)
#log = logging.getLogger(__name__)
#handler = logging.handlers.RotatingFileHandler('threat-feeds-task.log',maxbytes=100000,backupCount=5)
#formatter = logging.Formatter('%(asctime)s- %(name)s - %(levelname)s - %(message)s')
#handler.setFormatter(formatter)
#log.addHandler(handler)

# setup logging
logging.basicConfig(stream = sys.stdout, level = logging.DEBUG)
log = logging.getLogger(__name__)


class Threat_intelligence_base(object):

    def __init__(self, feed_url = '', proxy_enabled=None, proxy_host=None, proxy_port=None, proxy_user=None, proxy_password=None, proxy_auth=None):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_password = proxy_password
        self.proxy_enabled = proxy_enabled
        self.feed_url = feed_url
        self.feed_data = None
        self.indictor_dict = {
                              'ip':'Intel::ADDR',
                              'url':'Intel::URL',
                              'domain':'Intel::DOMAIN',
                              'hash':'Intel::FILE_HASH',
                              'software':'Intel::SOFTWARE',
                             }

        self.auth_type = proxy_auth

    def get_indicator(self,ind_type):
        try:
            return self.indicator_dict(ind_type)

        except Exception:
            return '-'

    def download_feed_using_request(self):

        try:
            if self.proxy_enabled:
                if (self.auth_type).lower() == 'digest':
                    proxy_dict = {
                        'http':'http://%s:%s' % (self.proxy_host, self.proxy_port),
                        'https':'http://%s:%s' % (self.proxy_host, self.proxy_port)
                    }

                    auth_details = HTTPProxyDigestAuth(self.proxy_user,self.proxy_password)

                    response = requests.get(self.feed_url, proxies = proxy_dict, auth = auth_details, verify=False)

                elif (self.auth_type).lower() == 'basic':
                    #'http':'http://user:pass@url:port'
                    proxy_dict = {
                        'http':'http://%s:%s@%s:%s' % (self.proxy_user, self.proxy_password,self.proxy_host, self.proxy_port),
                        'https':'http://%s:%s@%s:%s' % (self.proxy_user, self.proxy_password,self.proxy_host, self.proxy_port)
                    }
                    response = requests.get(self.feed_url,proxies = proxy_dict)
            else:
                if self.feed_url:
                    response = requests.get(self.feed_url)
            if response.status_code == 200:
                self.feed_data = response.text
                log.debug("%s" % self.feed_data)

        except Exception, e:
            log.error("Error while writing threat intelligence feed data - %s " % e.message,exc_info=True)

    def download_feed(self):

        try:
            if self.proxy_enabled:
                if (self.auth_type).lower() == 'digest':
                    proxy_auth_mode = pycurl.HTTPAUTH_DIGEST
                    # proxy_auth_mode = pycurl.HTTPAUTH_BASIC
                elif (self.auth_type).lower() == 'basic':
                    proxy_auth_mode = pycurl.HTTPAUTH_BASIC
                output = StringIO.StringIO()
                curl_instance = pycurl.Curl()
                curl_instance.setopt(pycurl.USERAGENT, 'Mozilla/57.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36')
                curl_instance.setopt(pycurl.PROXY, self.proxy_host)
                curl_instance.setopt(pycurl.PROXYPORT, self.proxy_port)
                curl_instance.setopt(pycurl.PROXYAUTH, proxy_auth_mode)
                curl_instance.setopt(pycurl.PROXYUSERPWD, "{}:{}".format(self.proxy_user, self.proxy_password))
                curl_instance.setopt(curl_instance.URL, self.feed_url)
                curl_instance.setopt(curl_instance.WRITEDATA, output)
                curl_instance.perform()
                response = output.getvalue()
                curl_instance.close()   
                self.feed_data = response
            else:
                if self.feed_url:
                    response = requests.get(self.feed_url)
                    if response.status_code == 200:
                        self.feed_data = response.text
                        log.debug("%s" % self.feed_data)

        except Exception, e:
            log.error("Error while writing threat intelligence feed data - %s " % e.message,exc_info=True)


    def write_socket(self,host,port):
        raise NotImplementedError


    def write_csv(self,csv_file):
        try:
            if not csv_file:
                log.error("CSV file %s is not valid." % csv_file)
            else:			
                if not self.feed_data:
                    log.error(" There is no threat intelligence feed data for processing. Quitting...")
                    sys.exit(1)

            # write CSV file
            log.info("Writing CSV file %s" % csv_file)

            with open(csv_file,'w') as fp:
                fp.write('Feed URL: %s\n\r\n' % self.feed_url)
                for line in self.feed_data:
                    line = re.sub('\\r|\\n','',line)
                    if line:
                        fp.write(line + "," + "Malicious IP\n")		
            log.info("csv file is written successfully.")
        except Exception as exc:
            log.error("Error while writing threat intelligence feed to file: %s\n Error trackback: %s" % (exc, traceback.format_exc()))

    def write_yaml(self,yaml_file):
        try:
            if not yaml_file:
                log.error("YAML file %s is not valid." % yaml_file)
            else:	
                if not self.feed_data:
                    log.error(" There is no threat intelligence feed data for processing. Quitting...")
                    sys.exit(1)

            # write YAML file
            log.info("Writing yaml file %s" % yaml_file)
            yaml_file = open(yaml_file,'w')
            for line in self.feed_data:
                line = re.sub('\\r|\\n','',line)
                if line:
                    yaml_file.write("\"" + line + "\": \"YES\"" + "\n")
            yaml_file.close()
            log.info("yaml file is written successfully.")

        except Exception as exc:
            log.error("Error while writing threat intelligence feed to file: %s\n Error trackback: %s" % (exc, traceback.format_exc()))


    def write_bro_csv(self, bro_csv_file,indicator_type,feed_source,feed_description,feed_url,raise_notice='T'):
        try:
            if not bro_csv_file:
                log.error("CSV file to be used along with Bro IDS %s is not valid." % csv_file)
                return
            else:			
                if not self.feed_data:
                    log.error(" There is no threat intelligence feed data for processing. Quitting...")
                    #sys.exit(1)
                    return 
            # write CSV file
            log.info("Writing Bro CSV file %s" % bro_csv_file)

            with open(bro_csv_file,'w') as fp:
                fp.write('#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\tmeta.do_notice\n')
                for line in self.feed_data:
                    line = re.sub('\\r|\\n','',line)
                    if line:
                        # indicator, indicator type, feed_source, feed_description, feed_url, raise_notice
                        file_line = '{}\t{}\t{}\t{}\t{}\t{}\n'.format(line.strip(),indicator_type,feed_source,feed_description,feed_url,raise_notice)
                        fp.write(file_line)		
                log.info("Bro CSV file is written successfully.")
        except Exception, exc:
            log.error("Error while writing threat intelligence feed to file: %s\n Error trackback: %s" % (exc.message, traceback.format_exc()))
 

    def update_elasticdb(self,el_host,el_port,el_index,el_doctype):
        try:

            # create elasticsearch instance
            el_instance = Manage_elasticsearch(el_host,
                                               int(el_port),
                                               el_index,
                                               el_doctype)
            el_health = el_instance.check_health()
            if not el_health:
                log.info("""Failed to connect to Elasticsearch server. Kindly re-check Elasticsearch settings
                and then try again""")
            else:

                # check if elasticsearch index exists. If not, create a new elastic index.
                index_present = el_instance.index_exists(el_index)
                if not index_present: 
                    response = el_instance.create_index(el_index)

                # update data to elasticsearch
                if self.feed_data:
                    el_instance.update_data(self.feed_data)

        except Exception, exc:
            log.error("Error while updating threat intelligence feed to elasticsearch database: %s\n Error Tracebck: %s" % (exc.message, traceback.format_exc()))
                 	

