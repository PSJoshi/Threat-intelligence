#!/usr/bin/env python
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from datetime import datetime 
import logging
import requests 
import sys 
import json 

# setup logging
logging.basicConfig(stream=sys.stdout,level=logging.INFO)
logger = logging.getLogger('site-response')

#default_request_body = {
#    "settings": {
#        "number_of_shards": 3,
#        "number_of_replicas": 1
#    }}

class Manage_elasticsearch():

    def __init__(self, el_host='127.0.0.1', el_port=9200, el_index='elastic', el_doc_type='elastic_doc', bulk_records=500):

        self.el_index = el_index
        self.el_doctype = el_doc_type
        self.el_host = el_host
        self.el_port = el_port
        self.el_instance = Elasticsearch([
                          { 'host':self.el_host, 
                            'port':int(self.el_port)
                          }])
        # min record to be used for batch update
        self.bulk_records = bulk_records 

    def index_exists(self, index_name):
        try:
            logger.info("Checking for presence of index %s" % index_name)
            self.el_index = index_name
            # if elastic index does not exists, create it.
            if not self.el_instance.indices.exists(self.el_index):
                #es_instance = create_elastic_index(self.el_host, self.el_port, self.el_index)
                return False
            else:
                logger.info("Elastic index %s is already present. Nothing to do!" % self.el_index)
                return True
        except Exception,exc:
            logger.error("Error while checking presence of elastic index %s -  %s " %(self.el_index, exc.message),exc_info=True)
            return False
 
    def check_health(self):
        try:

            response = requests.get('http://%s:%s' %(self.el_host, int(self.el_port) ))
            if response.status_code == 200:
                return True

        except Exception,exc:
            logger.error("Error while checking elasticsearch connection - %s" % exc.message, exc_info=True)

        return False
    
    def create_index(self, index_name, mapping_schema=None):

        try:

           self.el_index = index_name
 
           logger.info("Creating index %s in elasticsearch database" %index_name)

           if mapping_schema: 
               response = self.el_instance.indices.create(index=self.el_index, body=mapping_schema)
           else:
               response = self.el_instance.indices.create(index=self.el_index)

           logger.info("Elastic search index %s is created successfully" % self.el_index)

           return True
 
        except Exception,exc:
            logger.error("Error while creating elasticsearch index - %s" % exc.message, exc_info=True)
            return False

    def update_data(self, data, additional_info = None):
    
        try:
            insert_data = list()
            cnt = 0
            for item in data:
                ip_data = dict()
                if item:
                    ip_data = { 'ts':datetime.today().utcnow().isoformat(),
                                'ip': item,
                                'confidence':'75',
                                'severity':'high'
                               }

                    #additional context 
                    if type(additional_info) is dict:
                        ip_data.update(additional_info)

                    # not recommended
                    #self.el_instance.index(index=self.el_index,doc_type=self.el_doctype,body=ip_data}
                    data = {'_index': self.el_index, '_type': self.el_doctype,'_source': json.dumps(ip_data, separators =(',',':'))}
                    insert_data.append(data)
                    cnt = cnt + 1   
                    if cnt % self.bulk_records == 0:
                        # elasticsearch helper scripts
                        helpers.bulk(self.el_instance,insert_data)
                        logger.info("Indexed %d, working on next %s" %(cnt,self.bulk_records))
                        insert_data = list()
            if insert_data:
                helpers.bulk(self.el_instance, insert_data)

            logger.info("Indexed %d" % cnt)        

        except Exception, exc:
            logger.error("Error while updating data to elasticsearch - %s" %exc.message, exc_info=True)   

