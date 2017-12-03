#!/usr/bin/env python
import requests
import socket
import logging
import re
import sys
import traceback
import os
from threat_intelligence_base import Threat_intelligence_base
from utils.manage_elasticsearch import Manage_elasticsearch

# set up rotating file handler
#logging.basicConfig(level=logging.INFO)
#log = logging.getLogger('threat-feeds-task-logger')
#handler = logging.handlers.RotatingFileHandler('threat-feeds-task.log',maxbytes=100000,backupCount=5)
#formatter = logging.Formatter('%(asctime)s- %(name)s - %(levelname)s - %(message)s')
#handler.setFormatter(formatter)
#log.addHandler(handler)

# setup logging
logging.basicConfig(stream = sys.stdout, level = logging.DEBUG)
log = logging.getLogger(__name__)

class Abuse_ssh_blacklist(Threat_intelligence_base):

    def __init__(self,feed_url='',proxy_enabled='no',proxy_host=None,proxy_port=None,proxy_user=None,proxy_password=None,proxy_auth=None):
        super(Abuse_ssh_blacklist, self).__init__(feed_url,proxy_enabled,proxy_host,proxy_port,proxy_user,proxy_password,proxy_auth)
        self.cls_name = self.__class__.__name__

    def process_feed(self, feed_outputs=None):
        try:
            self.download_feed()
            if self.feed_data:
                # clean up data
                self.feed_data = self.feed_data.split('\n')
                # ignore first 9 entries as it contains generic information
                self.feed_data = self.feed_data[9:-1]				
                self.feed_data = [ item.split(',')[0] for item in self.feed_data if item != ''] 
                self._write_data(feed_outputs)
        except Exception,e:
            log.error("Error while processing threat intelligence feed - %s " % e.message,exc_info=True)
  

    def _write_data(self,feed_details):

        try:
            output_modes = feed_details['output']

            if feed_details.has_key('contains') and feed_details['contains']:
                indicator_type = self.get_indicator(feed_details['contains'])
            else: indicator_type = '-'

            feed_source = feed_details['name']
            feed_description = feed_details['description']
            feed_url = feed_details['url']
            raise_notice='T'
            for out_mode in output_modes:
                if out_mode['type'].lower() in ['csv','yaml','bro_csv']:  

                    log.info("file-type: %s , out file: %s " % (out_mode['type'], out_mode['file_path']) ) 

                    if out_mode['type'].lower() == 'csv' and out_mode['enabled']:
                        if out_mode['file_path']:
                            file_path = out_mode['file_path']
                        else:
                            file_name = self.cls_name + '.csv'
                            file_path = os.path.join(os.path.sep,os.getcwd(),file_name)
                        self.write_csv(file_path)

                    elif out_mode['type'].lower() == 'yaml' and out_mode['enabled']:
                        if out_mode['file_path']:
                            file_path = out_mode['file_path']
                        else:
                            file_name = self.cls_name + '.yaml'
                            file_path = os.path.join(os.path.sep,os.getcwd(),file_name)
                        self.write_yaml(file_path)

                    elif out_mode['type'].lower() == 'bro_csv' and out_mode['enabled']:
                        if out_mode['file_path']:
                            file_path = out_mode['file_path']
                        else:
                            file_name = 'bro_' + self.cls_name + '.csv'
                            file_path = os.path.join(os.path.sep,os.getcwd(),file_name)
                        self.write_bro_csv(file_path,indicator_type,feed_source,feed_description,feed_url,raise_notice) 

                elif out_mode['type'].lower() == 'elastic' and out_mode['enabled'] :   

                    log.info("host: %s port:%s index: %s doc_type: %s" %(out_mode['host'],out_mode['port'], out_mode['index'], out_mode['doc_type']))
                    # update elasticsearch database
                    self.update_elasticdb(out_mode['host'], int(out_mode['port']), out_mode['index'], out_mode['doc_type'])    

        except Exception, exc:
            log.error("Error while writing threat intelligence feed data - %s " % exc.message, exc_info=True)

